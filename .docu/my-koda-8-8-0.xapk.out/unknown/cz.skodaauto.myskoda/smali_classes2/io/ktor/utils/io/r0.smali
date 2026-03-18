.class public final Lio/ktor/utils/io/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# instance fields
.field public final d:Lio/ktor/utils/io/d0;

.field public final e:Lpx0/g;


# direct methods
.method public constructor <init>(Lio/ktor/utils/io/d0;Lpx0/g;)V
    .locals 1

    .line 1
    const-string v0, "coroutineContext"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lio/ktor/utils/io/r0;->d:Lio/ktor/utils/io/d0;

    .line 10
    .line 11
    iput-object p2, p0, Lio/ktor/utils/io/r0;->e:Lpx0/g;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/r0;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method
