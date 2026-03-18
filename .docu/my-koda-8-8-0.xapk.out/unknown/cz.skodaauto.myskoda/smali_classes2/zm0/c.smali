.class public final synthetic Lzm0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lzm0/c;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lzm0/c;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lcz/myskoda/api/bff_maps/v3/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {}, Lcz/myskoda/api/bff_maps/v3/infrastructure/ApiClient;->c()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_1
    new-instance p0, Lvw0/d;

    .line 17
    .line 18
    invoke-direct {p0}, Lvw0/d;-><init>()V

    .line 19
    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_2
    new-instance p0, Lcom/squareup/moshi/Moshi$Builder;

    .line 23
    .line 24
    invoke-direct {p0}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lbx/d;

    .line 28
    .line 29
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/Moshi$Builder;->a(Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Lcom/squareup/moshi/Moshi;

    .line 36
    .line 37
    invoke-direct {v0, p0}, Lcom/squareup/moshi/Moshi;-><init>(Lcom/squareup/moshi/Moshi$Builder;)V

    .line 38
    .line 39
    .line 40
    return-object v0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
