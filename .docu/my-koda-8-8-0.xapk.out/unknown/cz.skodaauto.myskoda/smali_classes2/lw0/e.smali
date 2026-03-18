.class public final Llw0/e;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public e:I

.field public f:Law0/c;

.field public g:Law0/h;

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lc2/k;

.field public j:I


# direct methods
.method public constructor <init>(Lc2/k;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Llw0/e;->i:Lc2/k;

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
    iput-object p1, p0, Llw0/e;->h:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Llw0/e;->j:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Llw0/e;->j:I

    .line 9
    .line 10
    iget-object p1, p0, Llw0/e;->i:Lc2/k;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lc2/k;->s(Lrx0/c;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
