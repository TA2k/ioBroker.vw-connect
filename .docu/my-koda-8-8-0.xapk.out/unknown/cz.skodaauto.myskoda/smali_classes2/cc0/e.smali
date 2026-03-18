.class public final Lcc0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcc0/a;


# direct methods
.method public constructor <init>(Lcc0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcc0/e;->a:Lcc0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Ldc0/b;

    .line 2
    .line 3
    iget-object p1, p1, Ldc0/b;->a:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcc0/e;->a:Lcc0/a;

    .line 6
    .line 7
    check-cast p0, Lac0/w;

    .line 8
    .line 9
    iget-object v0, p0, Lac0/w;->j:Lpx0/g;

    .line 10
    .line 11
    new-instance v1, La60/f;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x4

    .line 15
    invoke-direct {v1, v3, p0, p1, v2}, La60/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    invoke-static {v0, v1, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
