.class public final Lcc0/h;
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
    iput-object p1, p0, Lcc0/h;->a:Lcc0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lcc0/h;->a:Lcc0/a;

    .line 4
    .line 5
    check-cast p0, Lac0/w;

    .line 6
    .line 7
    iget-object p1, p0, Lac0/w;->j:Lpx0/g;

    .line 8
    .line 9
    new-instance v0, Lac0/f;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, p0, v1, v2}, Lac0/f;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1, v0, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
