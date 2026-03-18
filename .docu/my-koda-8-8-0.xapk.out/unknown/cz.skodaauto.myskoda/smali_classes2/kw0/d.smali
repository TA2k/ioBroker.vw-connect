.class public abstract Lkw0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvw0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    const-class v1, Lkw0/h;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :try_start_0
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 10
    .line 11
    .line 12
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    const/4 v1, 0x0

    .line 15
    :goto_0
    new-instance v2, Lzw0/a;

    .line 16
    .line 17
    invoke-direct {v2, v0, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lvw0/a;

    .line 21
    .line 22
    const-string v1, "ResponseAdapterAttributeKey"

    .line 23
    .line 24
    invoke-direct {v0, v1, v2}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lkw0/d;->a:Lvw0/a;

    .line 28
    .line 29
    return-void
.end method

.method public static final a(Lkw0/c;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "urlString"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lkw0/c;->a:Low0/z;

    .line 12
    .line 13
    invoke-static {p0, p1}, Low0/a0;->b(Low0/z;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
