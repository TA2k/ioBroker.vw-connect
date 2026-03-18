.class public final Lk8/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Lcom/salesforce/marketingcloud/analytics/piwama/m;

.field public static final h:Lcom/salesforce/marketingcloud/analytics/piwama/m;


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:[Lk8/m;

.field public c:I

.field public d:I

.field public e:I

.field public f:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lk8/n;->g:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 9
    .line 10
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 11
    .line 12
    const/16 v1, 0xd

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lk8/n;->h:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x5

    .line 5
    new-array v0, v0, [Lk8/m;

    .line 6
    .line 7
    iput-object v0, p0, Lk8/n;->b:[Lk8/m;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lk8/n;->a:Ljava/util/ArrayList;

    .line 15
    .line 16
    const/4 v0, -0x1

    .line 17
    iput v0, p0, Lk8/n;->c:I

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(IF)V
    .locals 5

    .line 1
    iget v0, p0, Lk8/n;->c:I

    .line 2
    .line 3
    iget-object v1, p0, Lk8/n;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eq v0, v2, :cond_0

    .line 7
    .line 8
    sget-object v0, Lk8/n;->g:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 9
    .line 10
    invoke-static {v1, v0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 11
    .line 12
    .line 13
    iput v2, p0, Lk8/n;->c:I

    .line 14
    .line 15
    :cond_0
    iget v0, p0, Lk8/n;->f:I

    .line 16
    .line 17
    iget-object v3, p0, Lk8/n;->b:[Lk8/m;

    .line 18
    .line 19
    if-lez v0, :cond_1

    .line 20
    .line 21
    sub-int/2addr v0, v2

    .line 22
    iput v0, p0, Lk8/n;->f:I

    .line 23
    .line 24
    aget-object v0, v3, v0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    new-instance v0, Lk8/m;

    .line 28
    .line 29
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    :goto_0
    iget v2, p0, Lk8/n;->d:I

    .line 33
    .line 34
    add-int/lit8 v4, v2, 0x1

    .line 35
    .line 36
    iput v4, p0, Lk8/n;->d:I

    .line 37
    .line 38
    iput v2, v0, Lk8/m;->a:I

    .line 39
    .line 40
    iput p1, v0, Lk8/m;->b:I

    .line 41
    .line 42
    iput p2, v0, Lk8/m;->c:F

    .line 43
    .line 44
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    iget p2, p0, Lk8/n;->e:I

    .line 48
    .line 49
    add-int/2addr p2, p1

    .line 50
    iput p2, p0, Lk8/n;->e:I

    .line 51
    .line 52
    :cond_2
    :goto_1
    iget p1, p0, Lk8/n;->e:I

    .line 53
    .line 54
    const/16 p2, 0x7d0

    .line 55
    .line 56
    if-le p1, p2, :cond_4

    .line 57
    .line 58
    add-int/lit16 p1, p1, -0x7d0

    .line 59
    .line 60
    const/4 p2, 0x0

    .line 61
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    check-cast v0, Lk8/m;

    .line 66
    .line 67
    iget v2, v0, Lk8/m;->b:I

    .line 68
    .line 69
    if-gt v2, p1, :cond_3

    .line 70
    .line 71
    iget p1, p0, Lk8/n;->e:I

    .line 72
    .line 73
    sub-int/2addr p1, v2

    .line 74
    iput p1, p0, Lk8/n;->e:I

    .line 75
    .line 76
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    iget p1, p0, Lk8/n;->f:I

    .line 80
    .line 81
    const/4 p2, 0x5

    .line 82
    if-ge p1, p2, :cond_2

    .line 83
    .line 84
    add-int/lit8 p2, p1, 0x1

    .line 85
    .line 86
    iput p2, p0, Lk8/n;->f:I

    .line 87
    .line 88
    aput-object v0, v3, p1

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_3
    sub-int/2addr v2, p1

    .line 92
    iput v2, v0, Lk8/m;->b:I

    .line 93
    .line 94
    iget p2, p0, Lk8/n;->e:I

    .line 95
    .line 96
    sub-int/2addr p2, p1

    .line 97
    iput p2, p0, Lk8/n;->e:I

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_4
    return-void
.end method

.method public final b()F
    .locals 5

    .line 1
    iget v0, p0, Lk8/n;->c:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lk8/n;->a:Ljava/util/ArrayList;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    sget-object v0, Lk8/n;->h:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 9
    .line 10
    invoke-static {v2, v0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 11
    .line 12
    .line 13
    iput v1, p0, Lk8/n;->c:I

    .line 14
    .line 15
    :cond_0
    iget p0, p0, Lk8/n;->e:I

    .line 16
    .line 17
    int-to-float p0, p0

    .line 18
    const/high16 v0, 0x3f000000    # 0.5f

    .line 19
    .line 20
    mul-float/2addr v0, p0

    .line 21
    move p0, v1

    .line 22
    :goto_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ge v1, v3, :cond_2

    .line 27
    .line 28
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lk8/m;

    .line 33
    .line 34
    iget v4, v3, Lk8/m;->b:I

    .line 35
    .line 36
    add-int/2addr p0, v4

    .line 37
    int-to-float v4, p0

    .line 38
    cmpl-float v4, v4, v0

    .line 39
    .line 40
    if-ltz v4, :cond_1

    .line 41
    .line 42
    iget p0, v3, Lk8/m;->c:F

    .line 43
    .line 44
    return p0

    .line 45
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-eqz p0, :cond_3

    .line 53
    .line 54
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 55
    .line 56
    return p0

    .line 57
    :cond_3
    const/4 p0, 0x1

    .line 58
    invoke-static {v2, p0}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lk8/m;

    .line 63
    .line 64
    iget p0, p0, Lk8/m;->c:F

    .line 65
    .line 66
    return p0
.end method
