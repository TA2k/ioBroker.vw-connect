.class public final synthetic Lpx/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;


# direct methods
.method public synthetic constructor <init>(Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;I)V
    .locals 0

    .line 1
    iput p2, p0, Lpx/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lpx/a;->e:Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lpx/a;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lpx/a;->e:Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;)Ld01/g0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    invoke-static {p0}, Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;)Ld01/g0;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_1
    invoke-static {p0}, Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;->a(Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;)Lretrofit2/Retrofit$Builder;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
