.class public final Lp60/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lln0/l;


# direct methods
.method public constructor <init>(Lln0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp60/g0;->a:Lln0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    iget-object p0, p0, Lp60/g0;->a:Lln0/l;

    .line 4
    .line 5
    const-string p2, "cardId"

    .line 6
    .line 7
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p2, p0, Lln0/l;->a:Lxl0/f;

    .line 11
    .line 12
    new-instance v0, La2/c;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/16 v2, 0x1c

    .line 16
    .line 17
    invoke-direct {v0, v2, p0, p1, v1}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, v0}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method
