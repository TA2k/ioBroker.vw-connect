.class public final Lam0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcu0/d;

.field public final b:Lam0/t;

.field public final c:Lam0/c;


# direct methods
.method public constructor <init>(Lcu0/d;Lam0/t;Lam0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lam0/l;->a:Lcu0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lam0/l;->b:Lam0/t;

    .line 7
    .line 8
    iput-object p3, p0, Lam0/l;->c:Lam0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lam0/l;->a:Lcu0/d;

    .line 4
    .line 5
    iget-object p1, p1, Lcu0/d;->a:Lcu0/h;

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lau0/g;

    .line 9
    .line 10
    iget-object p1, v1, Lau0/g;->c:Lyy0/i1;

    .line 11
    .line 12
    new-instance v0, Lau0/b;

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, 0x0

    .line 16
    const-string v2, "environment"

    .line 17
    .line 18
    const/4 v3, 0x1

    .line 19
    invoke-direct/range {v0 .. v5}, Lau0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    new-instance p2, Lne0/n;

    .line 23
    .line 24
    invoke-direct {p2, v0, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 25
    .line 26
    .line 27
    new-instance p1, Lac/l;

    .line 28
    .line 29
    const/4 v0, 0x3

    .line 30
    invoke-direct {p1, v0, p2, v2}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    new-instance p2, Lac/l;

    .line 34
    .line 35
    const/4 v0, 0x4

    .line 36
    invoke-direct {p2, v0, p1, v1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-static {p2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    new-instance p2, La50/h;

    .line 44
    .line 45
    const/4 v0, 0x5

    .line 46
    invoke-direct {p2, p1, v0}, La50/h;-><init>(Lyy0/i;I)V

    .line 47
    .line 48
    .line 49
    new-instance p1, Lam0/i;

    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    invoke-direct {p1, p2, v0}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    new-instance p2, Lac/l;

    .line 56
    .line 57
    const/4 v0, 0x1

    .line 58
    invoke-direct {p2, v0, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-object p2
.end method
