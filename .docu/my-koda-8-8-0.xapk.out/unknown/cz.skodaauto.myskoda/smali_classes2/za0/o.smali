.class public final Lza0/o;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lza0/p;

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lza0/q;

.field public g:I


# direct methods
.method public constructor <init>(Lza0/q;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lza0/o;->f:Lza0/q;

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
    iput-object p1, p0, Lza0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lza0/o;->g:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lza0/o;->g:I

    .line 9
    .line 10
    iget-object p1, p0, Lza0/o;->f:Lza0/q;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lza0/q;->b(Lrx0/c;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    return-object p0
.end method
