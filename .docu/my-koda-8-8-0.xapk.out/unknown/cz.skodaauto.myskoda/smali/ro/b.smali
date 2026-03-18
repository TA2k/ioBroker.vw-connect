.class public final synthetic Lro/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# static fields
.field public static final synthetic d:Lro/b;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lro/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lro/b;->d:Lro/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 2

    .line 1
    check-cast p1, Ljo/d;

    .line 2
    .line 3
    check-cast p2, Ljo/d;

    .line 4
    .line 5
    iget-object p0, p1, Ljo/d;->d:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v0, p2, Ljo/d;->d:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    iget-object p0, p1, Ljo/d;->d:Ljava/lang/String;

    .line 16
    .line 17
    iget-object p1, p2, Ljo/d;->d:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_0
    invoke-virtual {p1}, Ljo/d;->x0()J

    .line 25
    .line 26
    .line 27
    move-result-wide p0

    .line 28
    invoke-virtual {p2}, Ljo/d;->x0()J

    .line 29
    .line 30
    .line 31
    move-result-wide v0

    .line 32
    cmp-long p0, p0, v0

    .line 33
    .line 34
    return p0
.end method
