.class public final Lh2/m6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh2/n6;


# static fields
.field public static final a:Lh2/m6;

.field public static final b:Lc1/f1;

.field public static final c:Lc1/f1;

.field public static final d:Lc1/f1;

.field public static final e:Lc1/f1;

.field public static final f:Lc1/f1;

.field public static final g:Lc1/f1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh2/m6;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/m6;->a:Lh2/m6;

    .line 7
    .line 8
    const v0, 0x3f666666    # 0.9f

    .line 9
    .line 10
    .line 11
    const/high16 v1, 0x442f0000    # 700.0f

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x4

    .line 15
    invoke-static {v0, v1, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sput-object v1, Lh2/m6;->b:Lc1/f1;

    .line 20
    .line 21
    const/high16 v1, 0x44af0000    # 1400.0f

    .line 22
    .line 23
    invoke-static {v0, v1, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    sput-object v1, Lh2/m6;->c:Lc1/f1;

    .line 28
    .line 29
    const/high16 v1, 0x43960000    # 300.0f

    .line 30
    .line 31
    invoke-static {v0, v1, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lh2/m6;->d:Lc1/f1;

    .line 36
    .line 37
    const/high16 v0, 0x44c80000    # 1600.0f

    .line 38
    .line 39
    const/high16 v1, 0x3f800000    # 1.0f

    .line 40
    .line 41
    invoke-static {v1, v0, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lh2/m6;->e:Lc1/f1;

    .line 46
    .line 47
    const v0, 0x456d8000    # 3800.0f

    .line 48
    .line 49
    .line 50
    invoke-static {v1, v0, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lh2/m6;->f:Lc1/f1;

    .line 55
    .line 56
    const/high16 v0, 0x44480000    # 800.0f

    .line 57
    .line 58
    invoke-static {v1, v0, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sput-object v0, Lh2/m6;->g:Lc1/f1;

    .line 63
    .line 64
    return-void
.end method
