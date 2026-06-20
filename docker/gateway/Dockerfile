FROM nginx:alpine
COPY docker/gateway/nginx.conf /etc/nginx/nginx.conf
COPY docker/gateway/conf.d/ /etc/nginx/conf.d/
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
