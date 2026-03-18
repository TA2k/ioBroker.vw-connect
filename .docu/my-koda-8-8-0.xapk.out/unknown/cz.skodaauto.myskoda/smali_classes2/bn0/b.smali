.class public final Lbn0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lgm0/m;


# direct methods
.method public constructor <init>(Lgm0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbn0/b;->a:Lgm0/m;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lbn0/a;

    .line 5
    .line 6
    sget-object v2, Lge0/a;->d:Lge0/a;

    .line 7
    .line 8
    new-instance v3, La7/o;

    .line 9
    .line 10
    const/16 v4, 0xc

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    invoke-direct {v3, v4, v1, p0, v5}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x3

    .line 17
    invoke-static {v2, v5, v5, v3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    return-object v0
.end method
