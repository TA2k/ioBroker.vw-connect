.class public final Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# static fields
.field static final DEFAULT_CAPACITY:I = 0xa


# instance fields
.field private array:[Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[TT;"
        }
    .end annotation
.end field

.field private size:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0xa

    .line 5
    .line 6
    new-array v0, v0, [Ljava/lang/Object;

    .line 7
    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->array:[Ljava/lang/Object;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 12
    .line 13
    return-void
.end method

.method private resizeArray(I)V
    .locals 3

    .line 1
    new-array p1, p1, [Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->array:[Ljava/lang/Object;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 7
    .line 8
    invoke-static {v0, v1, p1, v1, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->array:[Ljava/lang/Object;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public isEmpty()Z
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public pop()Ljava/lang/Object;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return-object v1

    .line 9
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->array:[Ljava/lang/Object;

    .line 10
    .line 11
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 12
    .line 13
    add-int/lit8 v3, v2, -0x1

    .line 14
    .line 15
    aget-object v3, v0, v3

    .line 16
    .line 17
    add-int/lit8 v4, v2, -0x1

    .line 18
    .line 19
    aput-object v1, v0, v4

    .line 20
    .line 21
    add-int/lit8 v2, v2, -0x1

    .line 22
    .line 23
    iput v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 24
    .line 25
    return-object v3
.end method

.method public push(Ljava/lang/Object;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)V"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 4
    .line 5
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->array:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length v2, v1

    .line 8
    if-ne v0, v2, :cond_0

    .line 9
    .line 10
    array-length v0, v1

    .line 11
    mul-int/lit8 v0, v0, 0x2

    .line 12
    .line 13
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->resizeArray(I)V

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->array:[Ljava/lang/Object;

    .line 17
    .line 18
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 19
    .line 20
    add-int/lit8 v2, v1, 0x1

    .line 21
    .line 22
    iput v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 23
    .line 24
    aput-object p1, v0, v1

    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 28
    .line 29
    const-string p1, "Null is not permitted as element in the stack"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public size()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/ArrayBasedStack;->size:I

    .line 2
    .line 3
    return p0
.end method
