.class public final Luu0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:Luu0/x;

.field public final synthetic e:Z

.field public final synthetic f:Z


# direct methods
.method public constructor <init>(Luu0/x;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luu0/t;->d:Luu0/x;

    .line 5
    .line 6
    iput-boolean p2, p0, Luu0/t;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Luu0/t;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lne0/s;

    .line 2
    .line 3
    iget-boolean v0, p0, Luu0/t;->e:Z

    .line 4
    .line 5
    iget-boolean v1, p0, Luu0/t;->f:Z

    .line 6
    .line 7
    iget-object p0, p0, Luu0/t;->d:Luu0/x;

    .line 8
    .line 9
    invoke-virtual {p0, p1, v0, v1, p2}, Luu0/x;->B(Lne0/s;ZZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    if-ne p0, p1, :cond_0

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0
.end method
