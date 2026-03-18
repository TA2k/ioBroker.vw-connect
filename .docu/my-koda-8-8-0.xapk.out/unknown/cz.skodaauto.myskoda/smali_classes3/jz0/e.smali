.class public final Ljz0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljz0/q;


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Lio/ktor/utils/io/g0;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Lio/ktor/utils/io/g0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljz0/e;->a:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Ljz0/e;->b:Lio/ktor/utils/io/g0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final test(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Ljz0/e;->b:Lio/ktor/utils/io/g0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lio/ktor/utils/io/g0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object p0, p0, Ljz0/e;->a:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
