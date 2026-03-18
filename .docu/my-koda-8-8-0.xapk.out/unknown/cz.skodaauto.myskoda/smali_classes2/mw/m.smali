.class public final Lmw/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmw/b;


# instance fields
.field public final a:Ljava/util/LinkedHashMap;

.field public final b:D

.field public final c:D

.field public final d:D


# direct methods
.method public constructor <init>(Lmw/l;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lmw/l;->c:Ljava/util/LinkedHashMap;

    .line 5
    .line 6
    iput-object v0, p0, Lmw/m;->a:Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    iget-object v0, p1, Lmw/l;->a:Ljava/lang/Double;

    .line 9
    .line 10
    const-wide/16 v1, 0x0

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-wide v3, v1

    .line 20
    :goto_0
    iput-wide v3, p0, Lmw/m;->b:D

    .line 21
    .line 22
    iget-object v0, p1, Lmw/l;->b:Ljava/lang/Double;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 27
    .line 28
    .line 29
    move-result-wide v1

    .line 30
    :cond_1
    iput-wide v1, p0, Lmw/m;->c:D

    .line 31
    .line 32
    iget-wide v0, p1, Lmw/l;->d:D

    .line 33
    .line 34
    iput-wide v0, p0, Lmw/m;->d:D

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final a()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lmw/m;->c:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final b()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lmw/m;->d:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final c()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lmw/m;->b:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final d()D
    .locals 4

    .line 1
    invoke-virtual {p0}, Lmw/m;->a()D

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p0}, Lmw/m;->c()D

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    sub-double/2addr v0, v2

    .line 10
    return-wide v0
.end method

.method public final e(Llw/e;)Lmw/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lmw/m;->a:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lmw/k;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    return-object p1

    .line 12
    :cond_0
    const/4 p1, 0x0

    .line 13
    invoke-static {p0, p1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lmw/k;

    .line 18
    .line 19
    return-object p0
.end method
