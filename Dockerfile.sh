#!/bin/bash
cat <<EOF
FROM $BASE_IMAGE
LABEL maintainer="Alexey Shaporin <a.shaporin@rbk.money>"
RUN mkdir -p /var/log/tokenkeeper
COPY ./_build/prod/rel/tokenkeeper /opt/tokenkeeper
WORKDIR /opt/tokenkeeper
CMD /opt/tokenkeeper/bin/tokenkeeper foreground
EXPOSE 8022
LABEL com.rbkmoney.$SERVICE_NAME.parent=$BASE_IMAGE_NAME \
      com.rbkmoney.$SERVICE_NAME.parent_tag=$BASE_IMAGE_TAG \
      com.rbkmoney.$SERVICE_NAME.build_img=build \
      com.rbkmoney.$SERVICE_NAME.build_img_tag=$BUILD_IMAGE_TAG \
      com.rbkmoney.$SERVICE_NAME.commit_id=$(git rev-parse HEAD) \
      com.rbkmoney.$SERVICE_NAME.commit_number=$(git rev-list --count HEAD) \
      com.rbkmoney.$SERVICE_NAME.branch=$( \
        if [ "HEAD" != $(git rev-parse --abbrev-ref HEAD) ]; then \
          echo $(git rev-parse --abbrev-ref HEAD); \
        elif [ -n "$BRANCH_NAME" ]; then \
          echo $BRANCH_NAME; \
        else \
          echo $(git name-rev --name-only HEAD); \
        fi)
EOF
