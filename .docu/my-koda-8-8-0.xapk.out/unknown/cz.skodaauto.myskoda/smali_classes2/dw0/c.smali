.class public final Ldw0/c;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lpx0/g;

.field public e:Lss/b;

.field public f:Lxw0/d;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ldw0/d;

.field public i:I


# direct methods
.method public constructor <init>(Ldw0/d;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ldw0/c;->h:Ldw0/d;

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
    .locals 6

    .line 1
    iput-object p1, p0, Ldw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Ldw0/c;->i:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Ldw0/c;->i:I

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x0

    .line 12
    iget-object v0, p0, Ldw0/c;->h:Ldw0/d;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x0

    .line 16
    move-object v5, p0

    .line 17
    invoke-virtual/range {v0 .. v5}, Ldw0/d;->a(Ld01/h0;Ld01/k0;Lpx0/g;Lss/b;Lrx0/c;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
