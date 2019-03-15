(in-package #:saluto)

(defclass oauth2-microsoftonline.com (oauth2-provider)
  ((oauth-login-url :accessor oauth-login-url)
   (access-token-query-url :accessor access-token-query-url)
   (userinfo-query-url :accessor userinfo-query-url)
   (config-url :reader config-url
               :initform "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
               :allocation :class)))

(defmethod shared-initialize :after ((provider oauth2-microsoftonline.com) slot-names
                                      &key &allow-other-keys)
  (let ((conf-obj (jsown:parse (babel:octets-to-string (drakma:http-request (config-url provider) :want-stream nil)))))
    (setf (oauth-login-url provider) (jsown:val conf-obj "authorization_endpoint")
          (access-token-query-url provider) (jsown:val conf-obj "token_endpoint")
          (userinfo-query-url provider) (jsown:val conf-obj "userinfo_endpoint"))))

(defmethod make-redirect-uri ((provider oauth2-microsoftonline.com) session redirect-uri)
  (declare (ignore session redirect-uri))
  (let ((url (restas:make-route-url 'receiver-route (list :provider (name provider) :states "")))
        (host (if (boundp 'hunchentoot:*request*)
                (hunchentoot:host)
                "localhost")))
    (setf (puri:uri-scheme url) (if (cl-ppcre:scan "^localhost" host) :http :https)
          (puri:uri-host url) host)
    (puri:render-uri url nil)))

(defmethod build-goto-path :around ((provider oauth2-microsoftonline.com)
                                    session
                                    redirect-uri)
  (append
   (call-next-method provider session redirect-uri)
   (list
    "response_type" "code"
    "scope" "openid"
    "state" (make-state session redirect-uri))))

(defmethod prepare-access-token-request :around ((provider
                                                  oauth2-microsoftonline.com)
                                                 code
                                                 goto-path)
  (let ((request (call-next-method provider code goto-path)))
    (setf (getf (cdr request) :parameters)
          (concatenate-params (append
                               (list
                                (cons "grant_type" "authorization_code"))
                               (getf (cdr request) :parameters)))
          (getf (cdr request) :method) :post
          (getf (cdr request) :accept) "application/json")
    (substitute :content :parameters request)))

(defmethod extract-access-token :around ((provider oauth2-microsoftonline.com)
                                         answer)
  (call-next-method provider (babel:octets-to-string answer :encoding :UTF-8)))

(defmethod prepare-userinfo-request ::around ((provider oauth2-microsoftonline.com)
                                              access-token)
  (list (userinfo-query-url provider)
        :additional-headers (list (cons "Authorization" (format nil "Bearer ~a" access-token)))))

(defmethod extract-userinfo :around ((provider oauth2-microsoftonline.com)
                                     answer)
  (call-next-method provider (babel:octets-to-string answer :encoding :UTF-8)))

(defmethod extract-userinfo ((provider oauth2-microsoftonline.com)
                             parsed-answer)
  (list :first-name (json-val parsed-answer "given_name")
        :last-name (json-val parsed-answer "family_name")
        :avatar (json-val parsed-answer "avatar_url")
        :email (json-val parsed-answer "email")
        :uid (json-val parsed-answer "id")))

