.class public final Llb0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Llb0/p;


# direct methods
.method public constructor <init>(Llb0/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/l;->a:Llb0/p;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Llb0/l;->a:Llb0/p;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-virtual {p0, p1}, Llb0/p;->b(Z)Lyy0/i;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    new-instance p1, Lk31/t;

    .line 11
    .line 12
    check-cast p0, Lzy0/j;

    .line 13
    .line 14
    const/16 p2, 0xf

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    invoke-direct {p1, p0, v0, p2}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    new-instance p0, Lyy0/m1;

    .line 21
    .line 22
    invoke-direct {p0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-object p0
.end method
