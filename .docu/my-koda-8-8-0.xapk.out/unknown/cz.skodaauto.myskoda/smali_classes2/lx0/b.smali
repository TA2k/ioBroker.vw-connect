.class public final Llx0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/coroutines/Continuation;


# instance fields
.field public d:Lwz0/x;

.field public e:Lkotlin/coroutines/Continuation;

.field public f:Ljava/lang/Object;


# virtual methods
.method public final getContext()Lpx0/g;
    .locals 0

    .line 1
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Llx0/b;->e:Lkotlin/coroutines/Continuation;

    .line 3
    .line 4
    iput-object p1, p0, Llx0/b;->f:Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method
