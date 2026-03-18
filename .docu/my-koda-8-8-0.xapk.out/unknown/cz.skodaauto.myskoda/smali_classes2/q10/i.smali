.class public final Lq10/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;

.field public final b:Lq10/c;


# direct methods
.method public constructor <init>(Lbn0/g;Lq10/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq10/i;->a:Lbn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lq10/i;->b:Lq10/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lr10/c;)Lac/l;
    .locals 3

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    const-string v1, "departure"

    .line 4
    .line 5
    iget-object p1, p1, Lr10/c;->d:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {v0, v1, p1}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lq10/i;->a:Lbn0/g;

    .line 11
    .line 12
    invoke-virtual {p1, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    new-instance v0, Lbq0/i;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    const/16 v2, 0x1d

    .line 20
    .line 21
    invoke-direct {v0, p0, v1, v2}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    new-instance p0, Lac/l;

    .line 25
    .line 26
    invoke-direct {p0, p1, v0}, Lac/l;-><init>(Lzy0/j;Lay0/k;)V

    .line 27
    .line 28
    .line 29
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lr10/c;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lq10/i;->a(Lr10/c;)Lac/l;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
