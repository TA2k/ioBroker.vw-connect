.class public final Lm8/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final o:Lha/c;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lm8/r;

.field public final c:Landroid/util/SparseArray;

.field public final d:Z

.field public final e:Lm8/c;

.field public final f:Lw7/r;

.field public final g:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public h:Li4/c;

.field public i:Lw7/t;

.field public j:Landroid/util/Pair;

.field public k:I

.field public l:I

.field public m:J

.field public n:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lha/c;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lha/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lm8/t;->o:Lha/c;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(La8/l;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, La8/l;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Landroid/content/Context;

    .line 7
    .line 8
    iput-object v0, p0, Lm8/t;->a:Landroid/content/Context;

    .line 9
    .line 10
    new-instance v0, Li4/c;

    .line 11
    .line 12
    invoke-direct {v0}, Li4/c;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lm8/t;->h:Li4/c;

    .line 16
    .line 17
    iget-object v0, p1, La8/l;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lm8/r;

    .line 20
    .line 21
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lm8/t;->b:Lm8/r;

    .line 25
    .line 26
    new-instance v0, Landroid/util/SparseArray;

    .line 27
    .line 28
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lm8/t;->c:Landroid/util/SparseArray;

    .line 32
    .line 33
    sget-object v0, Lhr/h0;->e:Lhr/f0;

    .line 34
    .line 35
    sget-object v0, Lhr/x0;->h:Lhr/x0;

    .line 36
    .line 37
    iget-boolean v0, p1, La8/l;->d:Z

    .line 38
    .line 39
    iput-boolean v0, p0, Lm8/t;->d:Z

    .line 40
    .line 41
    iget-object v0, p1, La8/l;->i:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Lw7/r;

    .line 44
    .line 45
    iput-object v0, p0, Lm8/t;->f:Lw7/r;

    .line 46
    .line 47
    new-instance v1, Lm8/c;

    .line 48
    .line 49
    iget-object p1, p1, La8/l;->g:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p1, Lm8/y;

    .line 52
    .line 53
    invoke-direct {v1, p1, v0}, Lm8/c;-><init>(Lm8/y;Lw7/r;)V

    .line 54
    .line 55
    .line 56
    iput-object v1, p0, Lm8/t;->e:Lm8/c;

    .line 57
    .line 58
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 59
    .line 60
    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 61
    .line 62
    .line 63
    iput-object p1, p0, Lm8/t;->g:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 64
    .line 65
    new-instance p1, Lt7/n;

    .line 66
    .line 67
    invoke-direct {p1}, Lt7/n;-><init>()V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Lt7/n;->a()Lt7/o;

    .line 71
    .line 72
    .line 73
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    iput-wide v0, p0, Lm8/t;->m:J

    .line 79
    .line 80
    const/4 p1, -0x1

    .line 81
    iput p1, p0, Lm8/t;->n:I

    .line 82
    .line 83
    const/4 p1, 0x0

    .line 84
    iput p1, p0, Lm8/t;->l:I

    .line 85
    .line 86
    return-void
.end method
