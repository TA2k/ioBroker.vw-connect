.class public final Lo40/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lm40/g;


# direct methods
.method public constructor <init>(Lm40/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo40/e0;->a:Lm40/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp40/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lo40/e0;->b(Lp40/b;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lp40/b;)Lyy0/m1;
    .locals 4

    .line 1
    iget-object p0, p0, Lo40/e0;->a:Lm40/g;

    .line 2
    .line 3
    const-string v0, "request"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lm40/g;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v1, Llo0/b;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x3

    .line 14
    invoke-direct {v1, v3, p0, p1, v2}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    new-instance p0, Lm40/e;

    .line 18
    .line 19
    const/4 p1, 0x7

    .line 20
    invoke-direct {p0, p1}, Lm40/e;-><init>(I)V

    .line 21
    .line 22
    .line 23
    new-instance p1, Lm40/e;

    .line 24
    .line 25
    const/16 v2, 0x8

    .line 26
    .line 27
    invoke-direct {p1, v2}, Lm40/e;-><init>(I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v1, p0, p1}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
