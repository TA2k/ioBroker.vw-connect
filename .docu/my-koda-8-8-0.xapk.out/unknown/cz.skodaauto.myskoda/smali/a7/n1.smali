.class public final La7/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:La7/n1;


# instance fields
.field public final a:[J

.field public final b:[Landroid/widget/RemoteViews;

.field public final c:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, La7/n1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [J

    .line 5
    .line 6
    new-array v1, v1, [Landroid/widget/RemoteViews;

    .line 7
    .line 8
    const/4 v3, 0x1

    .line 9
    invoke-direct {v0, v2, v1, v3}, La7/n1;-><init>([J[Landroid/widget/RemoteViews;I)V

    .line 10
    .line 11
    .line 12
    sput-object v0, La7/n1;->d:La7/n1;

    .line 13
    .line 14
    return-void
.end method

.method public constructor <init>([J[Landroid/widget/RemoteViews;I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La7/n1;->a:[J

    .line 5
    .line 6
    iput-object p2, p0, La7/n1;->b:[Landroid/widget/RemoteViews;

    .line 7
    .line 8
    iput p3, p0, La7/n1;->c:I

    .line 9
    .line 10
    array-length p1, p1

    .line 11
    array-length v0, p2

    .line 12
    if-ne p1, v0, :cond_3

    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    if-lt p3, p1, :cond_2

    .line 16
    .line 17
    new-instance p1, Ljava/util/ArrayList;

    .line 18
    .line 19
    array-length p3, p2

    .line 20
    invoke-direct {p1, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 21
    .line 22
    .line 23
    array-length p3, p2

    .line 24
    const/4 v0, 0x0

    .line 25
    :goto_0
    if-ge v0, p3, :cond_0

    .line 26
    .line 27
    aget-object v1, p2, v0

    .line 28
    .line 29
    invoke-virtual {v1}, Landroid/widget/RemoteViews;->getLayoutId()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    add-int/lit8 v0, v0, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-static {p1}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Ljava/util/Collection;

    .line 48
    .line 49
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    iget p2, p0, La7/n1;->c:I

    .line 54
    .line 55
    if-gt p1, p2, :cond_1

    .line 56
    .line 57
    return-void

    .line 58
    :cond_1
    new-instance p2, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string p3, "View type count is set to "

    .line 61
    .line 62
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget p0, p0, La7/n1;->c:I

    .line 66
    .line 67
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string p0, ", but the collection contains "

    .line 71
    .line 72
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string p0, " different layout ids"

    .line 79
    .line 80
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p1

    .line 97
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 98
    .line 99
    const-string p1, "View type count must be >= 1"

    .line 100
    .line 101
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 106
    .line 107
    const-string p1, "RemoteCollectionItems has different number of ids and views"

    .line 108
    .line 109
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw p0
.end method
