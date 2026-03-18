.class public abstract Lcw0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvy0/a0;

.field public static final b:Lvw0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvy0/a0;

    .line 2
    .line 3
    const-string v1, "call-context"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcw0/h;->a:Lvy0/a0;

    .line 9
    .line 10
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 11
    .line 12
    const-class v1, Lzv0/e;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :try_start_0
    sget-object v2, Lhy0/d0;->c:Lhy0/d0;

    .line 19
    .line 20
    invoke-static {v1, v2}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    .line 21
    .line 22
    .line 23
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    const/4 v1, 0x0

    .line 26
    :goto_0
    new-instance v2, Lzw0/a;

    .line 27
    .line 28
    invoke-direct {v2, v0, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Lvw0/a;

    .line 32
    .line 33
    const-string v1, "client-config"

    .line 34
    .line 35
    invoke-direct {v0, v1, v2}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 36
    .line 37
    .line 38
    sput-object v0, Lcw0/h;->b:Lvw0/a;

    .line 39
    .line 40
    return-void
.end method
