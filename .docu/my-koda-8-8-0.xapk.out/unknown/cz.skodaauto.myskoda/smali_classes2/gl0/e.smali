.class public final Lgl0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lgl0/c;

.field public final b:Lgl0/d;


# direct methods
.method public constructor <init>(Lgl0/c;Lgl0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgl0/e;->a:Lgl0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lgl0/e;->b:Lgl0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lhl0/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lgl0/e;->b(Lhl0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lhl0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lgl0/e;->a:Lgl0/c;

    .line 2
    .line 3
    check-cast v0, Lel0/a;

    .line 4
    .line 5
    const-string v1, "<set-?>"

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lel0/a;->c:Lhl0/b;

    .line 11
    .line 12
    iget-object p0, p0, Lgl0/e;->b:Lgl0/d;

    .line 13
    .line 14
    check-cast p0, Liy/b;

    .line 15
    .line 16
    sget-object p1, Lly/b;->Z1:Lly/b;

    .line 17
    .line 18
    invoke-interface {p0, p1}, Ltl0/a;->a(Lul0/f;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, v0, Lel0/a;->b:Lyy0/k1;

    .line 22
    .line 23
    invoke-static {p0, p2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
