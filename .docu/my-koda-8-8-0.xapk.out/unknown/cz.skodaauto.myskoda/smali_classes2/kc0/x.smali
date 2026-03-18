.class public final Lkc0/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcu0/d;


# direct methods
.method public constructor <init>(Lcu0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/x;->a:Lcu0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result v3

    .line 7
    iget-object p0, p0, Lkc0/x;->a:Lcu0/d;

    .line 8
    .line 9
    iget-object p0, p0, Lcu0/d;->a:Lcu0/h;

    .line 10
    .line 11
    move-object v1, p0

    .line 12
    check-cast v1, Lau0/g;

    .line 13
    .line 14
    iget-object p0, v1, Lau0/g;->c:Lyy0/i1;

    .line 15
    .line 16
    new-instance v0, Lau0/b;

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x0

    .line 20
    const-string v2, "auth"

    .line 21
    .line 22
    invoke-direct/range {v0 .. v5}, Lau0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance p1, Lne0/n;

    .line 26
    .line 27
    invoke-direct {p1, v0, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 28
    .line 29
    .line 30
    new-instance p0, Lac/l;

    .line 31
    .line 32
    const/4 p2, 0x3

    .line 33
    invoke-direct {p0, p2, p1, v2}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Lac/l;

    .line 37
    .line 38
    const/4 p2, 0x4

    .line 39
    invoke-direct {p1, p2, p0, v1}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    new-instance p0, Lam0/i;

    .line 43
    .line 44
    const/16 p2, 0xb

    .line 45
    .line 46
    invoke-direct {p0, p1, p2}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 47
    .line 48
    .line 49
    new-instance p1, Lam0/i;

    .line 50
    .line 51
    const/16 p2, 0xa

    .line 52
    .line 53
    invoke-direct {p1, p0, p2}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    new-instance p0, Lam0/i;

    .line 57
    .line 58
    const/16 p2, 0xc

    .line 59
    .line 60
    invoke-direct {p0, p1, p2}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    return-object p0
.end method
