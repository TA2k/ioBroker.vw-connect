.class public final Lal0/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/b1;

.field public final b:Lal0/d0;


# direct methods
.method public constructor <init>(Lal0/b1;Lal0/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/p1;->a:Lal0/b1;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/p1;->b:Lal0/d0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lbl0/l0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lal0/p1;->b(Lbl0/l0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lbl0/l0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lal0/p1;->b:Lal0/d0;

    .line 2
    .line 3
    check-cast v0, Lyk0/f;

    .line 4
    .line 5
    iput-object p1, v0, Lyk0/f;->a:Lbl0/l0;

    .line 6
    .line 7
    iget-object p0, p0, Lal0/p1;->a:Lal0/b1;

    .line 8
    .line 9
    invoke-virtual {p0}, Lal0/b1;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    iget-object p0, v0, Lyk0/f;->c:Lyy0/k1;

    .line 13
    .line 14
    invoke-static {p0, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method
