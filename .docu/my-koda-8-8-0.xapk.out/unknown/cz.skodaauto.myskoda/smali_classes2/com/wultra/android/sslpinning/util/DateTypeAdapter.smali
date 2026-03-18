.class public final Lcom/wultra/android/sslpinning/util/DateTypeAdapter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/m;
.implements Lcom/google/gson/s;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lcom/google/gson/m;",
        "Lcom/google/gson/s;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u00012\u0008\u0012\u0004\u0012\u00020\u00020\u0003B\u0007\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\u00a8\u0006\u0006"
    }
    d2 = {
        "Lcom/wultra/android/sslpinning/util/DateTypeAdapter;",
        "Lcom/google/gson/m;",
        "Ljava/util/Date;",
        "Lcom/google/gson/s;",
        "<init>",
        "()V",
        "library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/reflect/Type;)Lcom/google/gson/r;
    .locals 2

    .line 1
    check-cast p1, Ljava/util/Date;

    .line 2
    .line 3
    const-string p0, "src"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "typeOfSrc"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    const/16 p2, 0x3e8

    .line 18
    .line 19
    int-to-long v0, p2

    .line 20
    div-long/2addr p0, v0

    .line 21
    new-instance p2, Lcom/google/gson/r;

    .line 22
    .line 23
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {p2, p0}, Lcom/google/gson/r;-><init>(Ljava/lang/Number;)V

    .line 28
    .line 29
    .line 30
    return-object p2
.end method

.method public final b(Lcom/google/gson/n;Ljava/lang/reflect/Type;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string p0, "json"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "typeOfT"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Ljava/util/Date;

    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/google/gson/n;->c()J

    .line 14
    .line 15
    .line 16
    move-result-wide p1

    .line 17
    const/16 v0, 0x3e8

    .line 18
    .line 19
    int-to-long v0, v0

    .line 20
    mul-long/2addr p1, v0

    .line 21
    invoke-direct {p0, p1, p2}, Ljava/util/Date;-><init>(J)V

    .line 22
    .line 23
    .line 24
    return-object p0
.end method
