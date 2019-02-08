(ql:quickload '("cl-who" "restas" "saluto"))

(restas:define-module #:restas.test-saluto
  (:use #:cl))

(in-package #:restas.test-saluto)

(defvar *users* (make-hash-table :test #'equal))

(restas:mount-module saluto (#:saluto)
  (:url "auth/")
  (:inherit-parent-context t)
  (saluto:*providers* (list
                        (make-instance 'saluto:oauth2-google.com
                                       :name "google.com"
                                       :app-id "845600361011.apps.googleusercontent.com"
                                       :app-private-key "G90eET_kGV6kTLYyrhTvqBP3")
                        (make-instance 'saluto:oauth2-github.com
                                       :name "github.com"
                                       :app-id "ab844c69808d50d44904"
                                       :app-private-key "8c09f10e3a8991acbcfc3b7f6b81f647a785c4c6")
                        (make-instance 'saluto:oauth2-mail.ru
                                       :name "mail.ru"
                                       :app-id "712129"
                                       :app-private-key "eee171fb3b5d65a9d8dfb4e55659719e")
                        (make-instance 'saluto:oauth2-facebook.com
                                       :name "facebook.com"
                                       :app-id "390129604417832"
                                       :app-private-key "52f17dfdecdcec61c5806f937a8ae28d")
                        (make-instance 'saluto:oauth2-vk.com
                                       :name "vk.com"
                                       :app-id "3958122"
                                       :app-private-key "pDO8PPhlfKLDL3gGryjC")
                        (make-instance 'saluto:oauth2-microsoftonline.com
                                       :name "microsoftonline.com"
                                       :app-id "e3067a30-165b-4076-afb7-baa5bda2ccb2"
                                       :app-private-key "xqfrJIAN2530^nyxSMQ3$%-")))
  (saluto:*store-userinfo-fun*
   (lambda (info)
     (setf (gethash hunchentoot:*session* *users*) info)))
  (saluto:*logged-in-p-fun*
   (lambda ()
     (gethash hunchentoot:*session* *users* nil))))

(restas:define-route main ("" :method :get)
  (who:with-html-output-to-string (out)
    (:html
     (:head (:title "Testing saluto"))
     (:body
      (:h1 "Testing saluto")
      (if (gethash hunchentoot:*session* *users* nil)
          (let ((slots (gethash hunchentoot:*session* *users*)))
            (who:htm
             (:div (:img :src (getf slots :avatar) :style "float: left; padding-right: 10px;")
                   (:p (who:esc (format nil "~a ~a" (getf slots :last-name) (getf slots :first-name))))
                   (:p (:a :href (restas:genurl 'saluto.logout-route) "Logout")))))
          (who:htm 
           (:p (:a :href (restas:genurl 'saluto.login-with :provider "facebook.com")
                   "Login with FACEBOOK.COM"))
           (:p (:a :href (restas:genurl 'saluto.login-with :provider "github.com")
                   "Login with GITHUB.COM"))
           (:p (:a :href (restas:genurl 'saluto.login-with :provider "mail.ru")
                   "Login with MAIL.RU"))
           (:p (:a :href (restas:genurl 'saluto.login-with :provider "vk.com")
                   "Login with VK.COM"))
           (:p (:a :href (restas:genurl 'saluto.login-with :provider "google.com")
                   "Login with GOOGLE.COM"))
           (:p (:a :href (restas:genurl 'saluto.login-with :provider "microsoftonline.com")
                   "Login with MICROSOFTONLINE.COM"))
           (:p "Not logged in")))))))

(restas:start '#:restas.test-saluto :port 8080)
