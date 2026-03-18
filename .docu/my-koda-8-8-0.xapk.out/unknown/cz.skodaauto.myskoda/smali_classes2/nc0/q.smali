.class public final Lnc0/q;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ld01/k0;

.field public e:Lnc0/r;

.field public f:Lne0/t;

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lnc0/r;

.field public j:I


# direct methods
.method public constructor <init>(Lnc0/r;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lnc0/q;->i:Lnc0/r;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Lnc0/q;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lnc0/q;->j:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lnc0/q;->j:I

    .line 9
    .line 10
    iget-object p1, p0, Lnc0/q;->i:Lnc0/r;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-static {p1, v0, p0}, Lnc0/r;->b(Lnc0/r;Ld01/k0;Lrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    check-cast p0, Ljava/lang/String;

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    new-instance p1, Llc0/a;

    .line 27
    .line 28
    invoke-direct {p1, p0}, Llc0/a;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-object p1

    .line 32
    :cond_1
    return-object v0
.end method
