.class public final Lvy0/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final d:Lvy0/x;


# direct methods
.method public constructor <init>(Lvy0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvy0/o0;->d:Lvy0/x;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lvy0/o0;->d:Lvy0/x;

    .line 2
    .line 3
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 4
    .line 5
    invoke-static {p0, v0}, Laz0/b;->j(Lvy0/x;Lpx0/g;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Laz0/b;->i(Lvy0/x;Lpx0/g;Ljava/lang/Runnable;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lvy0/o0;->d:Lvy0/x;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvy0/x;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
