.class public final Lbq0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbq0/h;

.field public final b:Lkf0/o;

.field public final c:Lbq0/c;


# direct methods
.method public constructor <init>(Lbq0/h;Lkf0/o;Lbq0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbq0/o;->a:Lbq0/h;

    .line 5
    .line 6
    iput-object p2, p0, Lbq0/o;->b:Lkf0/o;

    .line 7
    .line 8
    iput-object p3, p0, Lbq0/o;->c:Lbq0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lbq0/o;->b:Lkf0/o;

    .line 4
    .line 5
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance p2, La90/c;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    const/16 v1, 0x8

    .line 13
    .line 14
    invoke-direct {p2, v0, p0, v1}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1, p2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p1, p0, Lbq0/o;->b:Lkf0/o;

    .line 2
    .line 3
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, La90/c;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    const/16 v2, 0x8

    .line 11
    .line 12
    invoke-direct {v0, v1, p0, v2}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
