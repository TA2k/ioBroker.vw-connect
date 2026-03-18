.class public final Ls41/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static volatile a:Lpw0/a;

.field public static final b:Ljava/util/LinkedHashSet;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 2
    .line 3
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 4
    .line 5
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Ls41/b;->a:Lpw0/a;

    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 14
    .line 15
    .line 16
    sput-object v0, Ls41/b;->b:Ljava/util/LinkedHashSet;

    .line 17
    .line 18
    return-void
.end method

.method public static a(Leb/j0;)V
    .locals 3

    .line 1
    sget-object v0, Ls41/b;->b:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Ls41/b;->a:Lpw0/a;

    .line 10
    .line 11
    new-instance v1, Lc00/p0;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-direct {v1, p0, v2}, Lc00/p0;-><init>(Leb/j0;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    const/4 p0, 0x3

    .line 18
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method
