.class public final Lqw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:C

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(CLjava/util/List;Ljava/util/ArrayList;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-char p1, p0, Lqw0/a;->a:C

    .line 5
    .line 6
    iput-object p2, p0, Lqw0/a;->b:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Lqw0/a;->c:Ljava/util/ArrayList;

    .line 9
    .line 10
    const/16 p1, 0x100

    .line 11
    .line 12
    new-array p2, p1, [Lqw0/a;

    .line 13
    .line 14
    const/4 p3, 0x0

    .line 15
    move v0, p3

    .line 16
    :goto_0
    if-ge v0, p1, :cond_4

    .line 17
    .line 18
    iget-object v1, p0, Lqw0/a;->c:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    const/4 v2, 0x0

    .line 25
    move v3, p3

    .line 26
    move-object v4, v2

    .line 27
    :cond_0
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_2

    .line 32
    .line 33
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    move-object v6, v5

    .line 38
    check-cast v6, Lqw0/a;

    .line 39
    .line 40
    iget-char v6, v6, Lqw0/a;->a:C

    .line 41
    .line 42
    if-ne v6, v0, :cond_0

    .line 43
    .line 44
    if-eqz v3, :cond_1

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_1
    const/4 v3, 0x1

    .line 48
    move-object v4, v5

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    if-nez v3, :cond_3

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_3
    move-object v2, v4

    .line 54
    :goto_2
    aput-object v2, p2, v0

    .line 55
    .line 56
    add-int/lit8 v0, v0, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_4
    return-void
.end method
