.class public final La90/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:La90/u;

.field public final b:Lfg0/d;


# direct methods
.method public constructor <init>(La90/u;Lfg0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La90/d;->a:La90/u;

    .line 5
    .line 6
    iput-object p2, p0, La90/d;->b:Lfg0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, La90/d;->b:Lfg0/d;

    .line 4
    .line 5
    invoke-virtual {p1}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    new-instance p2, Lrz/k;

    .line 12
    .line 13
    const/16 v0, 0x15

    .line 14
    .line 15
    invoke-direct {p2, p1, v0}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    invoke-static {p2, p1}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    new-instance p2, La90/c;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-direct {p2, v0, p0, v1}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p1, p2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
