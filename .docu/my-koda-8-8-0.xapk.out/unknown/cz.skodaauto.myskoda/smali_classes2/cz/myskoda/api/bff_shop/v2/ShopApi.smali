.class public interface abstract Lcz/myskoda/api/bff_shop/v2/ShopApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000Z\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J*\u0010\r\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\u00042\u0008\u0008\u0001\u0010\t\u001a\u00020\u00082\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\r\u0010\u000eJ*\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u000f\u001a\u00020\u00082\u0008\u0008\u0001\u0010\u0011\u001a\u00020\u0010H\u00a7@\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J \u0010\u0015\u001a\u0008\u0012\u0004\u0012\u00020\u00140\u00042\u0008\u0008\u0001\u0010\t\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0016\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\u00170\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J \u0010\u001b\u001a\u0008\u0012\u0004\u0012\u00020\u001a0\u00042\u0008\u0008\u0001\u0010\u000f\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0004\u0008\u001b\u0010\u0016J*\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u001e0\u00042\u0008\u0008\u0001\u0010\u001d\u001a\u00020\u001c2\u0008\u0008\u0001\u0010\u000f\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0004\u0008\u001f\u0010 \u00a8\u0006!\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_shop/v2/ShopApi;",
        "",
        "Lcz/myskoda/api/bff_shop/v2/ApplyVoucherRequestDto;",
        "applyVoucherRequestDto",
        "Lretrofit2/Response;",
        "Llx0/b0;",
        "applyVoucher",
        "(Lcz/myskoda/api/bff_shop/v2/ApplyVoucherRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "productCode",
        "Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;",
        "loyaltyProductsOrderRequestDto",
        "Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderDto;",
        "createLoyaltyProductsOrder",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "vin",
        "Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;",
        "subscriptionsOrderRequestDto",
        "createSubscriptionsOrder",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Ld01/v0;",
        "getLoyaltyProductImage",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsDto;",
        "getLoyaltyProducts",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_shop/v2/ShopSubscriptionsResponseDto;",
        "getShopSubscriptions",
        "",
        "includeUserData",
        "Lcz/myskoda/api/bff_shop/v2/UrlDto;",
        "getSkodaCubicTelecomLink",
        "(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract applyVoucher(Lcz/myskoda/api/bff_shop/v2/ApplyVoucherRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_shop/v2/ApplyVoucherRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_shop/v2/ApplyVoucherRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/shop/vouchers/apply"
    .end annotation
.end method

.method public abstract createLoyaltyProductsOrder(Ljava/lang/String;Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "productCode"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/shop/loyalty-products/{productCode}"
    .end annotation
.end method

.method public abstract createSubscriptionsOrder(Ljava/lang/String;Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/shop/subscriptions/{vin}/order"
    .end annotation
.end method

.method public abstract getLoyaltyProductImage(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "productCode"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Ld01/v0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/shop/loyalty-products/{productCode}/image"
    .end annotation
.end method

.method public abstract getLoyaltyProducts(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/shop/loyalty-products"
    .end annotation
.end method

.method public abstract getShopSubscriptions(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_shop/v2/ShopSubscriptionsResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/shop/subscriptions"
    .end annotation
.end method

.method public abstract getSkodaCubicTelecomLink(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Z
        .annotation runtime Lretrofit2/http/Query;
            value = "includeUserData"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_shop/v2/UrlDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/shop/cubic-link"
    .end annotation
.end method
