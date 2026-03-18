.class public final Lu9/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final d:I

.field public final e:Lu9/b;


# direct methods
.method public constructor <init>(ILu9/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lu9/f;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Lu9/f;->e:Lu9/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lu9/f;

    .line 2
    .line 3
    iget p0, p0, Lu9/f;->d:I

    .line 4
    .line 5
    iget p1, p1, Lu9/f;->d:I

    .line 6
    .line 7
    invoke-static {p0, p1}, Ljava/lang/Integer;->compare(II)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method
