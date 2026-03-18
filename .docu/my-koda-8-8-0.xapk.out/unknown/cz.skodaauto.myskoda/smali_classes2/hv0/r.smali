.class public final Lhv0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/w0;

.field public final b:Lhv0/t;


# direct methods
.method public constructor <init>(Lal0/w0;Lhv0/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/r;->a:Lal0/w0;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/r;->b:Lhv0/t;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lhv0/r;->b:Lhv0/t;

    .line 4
    .line 5
    invoke-virtual {p1}, Lhv0/t;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    iget-object p0, p0, Lhv0/r;->a:Lal0/w0;

    .line 12
    .line 13
    invoke-virtual {p0}, Lal0/w0;->invoke()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lyy0/i;

    .line 18
    .line 19
    new-instance p2, Lal0/y0;

    .line 20
    .line 21
    const/4 v0, 0x3

    .line 22
    const/4 v1, 0x7

    .line 23
    const/4 v2, 0x0

    .line 24
    invoke-direct {p2, v0, v2, v1}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lbn0/f;

    .line 28
    .line 29
    const/4 v1, 0x5

    .line 30
    invoke-direct {v0, p1, p0, p2, v1}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method
