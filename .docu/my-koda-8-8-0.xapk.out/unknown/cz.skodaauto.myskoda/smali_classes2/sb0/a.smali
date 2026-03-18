.class public final Lsb0/a;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public final synthetic e:Lsb0/b;

.field public f:I


# direct methods
.method public constructor <init>(Lsb0/b;Lrx0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lsb0/a;->e:Lsb0/b;

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
    iput-object p1, p0, Lsb0/a;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Lsb0/a;->f:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Lsb0/a;->f:I

    .line 9
    .line 10
    iget-object p1, p0, Lsb0/a;->e:Lsb0/b;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Lsb0/b;->a(Lrx0/c;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
