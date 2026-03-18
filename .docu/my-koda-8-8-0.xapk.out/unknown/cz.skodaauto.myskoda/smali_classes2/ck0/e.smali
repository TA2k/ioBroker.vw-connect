.class public final Lck0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lck0/b;

.field public final b:Lak0/c;


# direct methods
.method public constructor <init>(Lck0/b;Lak0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lck0/e;->a:Lck0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lck0/e;->b:Lak0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/UUID;)V
    .locals 4

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lge0/a;->d:Lge0/a;

    .line 7
    .line 8
    new-instance v1, Lc80/l;

    .line 9
    .line 10
    const/16 v2, 0xb

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v1, v2, p0, p1, v3}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x3

    .line 17
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/util/UUID;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lck0/e;->a(Ljava/util/UUID;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
