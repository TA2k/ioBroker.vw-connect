.class public final Lr6/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:Ljava/lang/ThreadLocal;


# instance fields
.field public final a:Landroidx/collection/a1;

.field public final b:Ljava/util/ArrayList;

.field public final c:Lpv/g;

.field public final d:Lm8/o;

.field public final e:Lb81/b;

.field public f:Z

.field public g:F

.field public h:Lb81/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lr6/b;->i:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lb81/b;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/collection/a1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lr6/b;->a:Landroidx/collection/a1;

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lr6/b;->b:Ljava/util/ArrayList;

    .line 18
    .line 19
    new-instance v0, Lpv/g;

    .line 20
    .line 21
    const/4 v2, 0x2

    .line 22
    invoke-direct {v0, p0, v2}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lr6/b;->c:Lpv/g;

    .line 26
    .line 27
    new-instance v0, Lm8/o;

    .line 28
    .line 29
    const/16 v2, 0xa

    .line 30
    .line 31
    invoke-direct {v0, p0, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lr6/b;->d:Lm8/o;

    .line 35
    .line 36
    iput-boolean v1, p0, Lr6/b;->f:Z

    .line 37
    .line 38
    const/high16 v0, 0x3f800000    # 1.0f

    .line 39
    .line 40
    iput v0, p0, Lr6/b;->g:F

    .line 41
    .line 42
    iput-object p1, p0, Lr6/b;->e:Lb81/b;

    .line 43
    .line 44
    return-void
.end method
