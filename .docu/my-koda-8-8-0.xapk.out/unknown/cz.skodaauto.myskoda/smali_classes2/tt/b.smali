.class public final Ltt/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ViewTreeObserver$OnDrawListener;


# instance fields
.field public final synthetic d:Lcom/google/firebase/perf/metrics/AppStartTrace;


# direct methods
.method public constructor <init>(Lcom/google/firebase/perf/metrics/AppStartTrace;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltt/b;->d:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onDraw()V
    .locals 1

    .line 1
    iget-object p0, p0, Ltt/b;->d:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 2
    .line 3
    iget v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->w:I

    .line 4
    .line 5
    add-int/lit8 v0, v0, 0x1

    .line 6
    .line 7
    iput v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->w:I

    .line 8
    .line 9
    return-void
.end method
