.class public final Lcom/google/android/filament/utils/Mat3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Mat3$Companion;,
        Lcom/google/android/filament/utils/Mat3$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0010\u000b\n\u0002\u0008\u0006\n\u0002\u0010\u0014\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0016\u0008\u0086\u0008\u0018\u0000 E2\u00020\u0001:\u0001EB%\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0006\u0010\u0007B\u0011\u0008\u0016\u0012\u0006\u0010\u0008\u001a\u00020\u0000\u00a2\u0006\u0004\u0008\u0006\u0010\tJ\u0018\u0010\u000c\u001a\u00020\u00022\u0006\u0010\u000b\u001a\u00020\nH\u0086\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rJ \u0010\u000c\u001a\u00020\u000f2\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\nH\u0086\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\u0010J\u0018\u0010\u000c\u001a\u00020\u00022\u0006\u0010\u000b\u001a\u00020\u0011H\u0086\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\u0012J \u0010\u000c\u001a\u00020\u000f2\u0006\u0010\u000b\u001a\u00020\u00112\u0006\u0010\u000e\u001a\u00020\nH\u0086\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\u0013J \u0010\u0014\u001a\u00020\u000f2\u0006\u0010\u000e\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\nH\u0086\u0002\u00a2\u0006\u0004\u0008\u0014\u0010\u0010J(\u0010\u0014\u001a\u00020\u00162\u0006\u0010\u000e\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0015\u001a\u00020\u000fH\u0086\u0002\u00a2\u0006\u0004\u0008\u0014\u0010\u0017J \u0010\u0018\u001a\u00020\u00162\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0015\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J(\u0010\u0018\u001a\u00020\u00162\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\n2\u0006\u0010\u0015\u001a\u00020\u000fH\u0086\u0002\u00a2\u0006\u0004\u0008\u0018\u0010\u0017J\u0010\u0010\u001a\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ\u0010\u0010\u001c\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008\u001c\u0010\u001bJ\u0010\u0010\u001d\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008\u001d\u0010\u001bJ\u0018\u0010\u001e\u001a\u00020\u00002\u0006\u0010\u0015\u001a\u00020\u000fH\u0086\u0002\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u0018\u0010 \u001a\u00020\u00002\u0006\u0010\u0015\u001a\u00020\u000fH\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010\u001fJ\u0018\u0010!\u001a\u00020\u00002\u0006\u0010\u0015\u001a\u00020\u000fH\u0086\u0002\u00a2\u0006\u0004\u0008!\u0010\u001fJ\u0018\u0010\"\u001a\u00020\u00002\u0006\u0010\u0015\u001a\u00020\u000fH\u0086\u0002\u00a2\u0006\u0004\u0008\"\u0010\u001fJ\"\u0010$\u001a\u00020\u00002\u0006\u0010\u0015\u001a\u00020\u000f2\u0008\u0008\u0002\u0010#\u001a\u00020\u000fH\u0086\u0008\u00a2\u0006\u0004\u0008$\u0010%J\"\u0010\'\u001a\u00020&2\u0006\u0010\u0015\u001a\u00020\u000f2\u0008\u0008\u0002\u0010#\u001a\u00020\u000fH\u0086\u0008\u00a2\u0006\u0004\u0008\'\u0010(J\u0018\u0010!\u001a\u00020\u00002\u0006\u0010\u0008\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008!\u0010)J\"\u0010$\u001a\u00020\u00002\u0006\u0010\u0008\u001a\u00020\u00002\u0008\u0008\u0002\u0010#\u001a\u00020\u000fH\u0086\u0008\u00a2\u0006\u0004\u0008$\u0010*J\"\u0010\'\u001a\u00020&2\u0006\u0010\u0008\u001a\u00020\u00002\u0008\u0008\u0002\u0010#\u001a\u00020\u000fH\u0086\u0008\u00a2\u0006\u0004\u0008\'\u0010+J\u0018\u0010!\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008!\u0010,J\r\u0010.\u001a\u00020-\u00a2\u0006\u0004\u0008.\u0010/J\u000f\u00101\u001a\u000200H\u0016\u00a2\u0006\u0004\u00081\u00102J\u0010\u00103\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u00083\u00104J\u0010\u00105\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u00085\u00104J\u0010\u00106\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u00086\u00104J.\u00107\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u00087\u00108J\u0010\u00109\u001a\u00020\nH\u00d6\u0001\u00a2\u0006\u0004\u00089\u0010:J\u001a\u0010\'\u001a\u00020&2\u0008\u0010;\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u0008\'\u0010<R\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010=\u001a\u0004\u0008>\u00104\"\u0004\u0008?\u0010@R\"\u0010\u0004\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010=\u001a\u0004\u0008A\u00104\"\u0004\u0008B\u0010@R\"\u0010\u0005\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0005\u0010=\u001a\u0004\u0008C\u00104\"\u0004\u0008D\u0010@\u00a8\u0006F"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Mat3;",
        "",
        "Lcom/google/android/filament/utils/Float3;",
        "x",
        "y",
        "z",
        "<init>",
        "(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V",
        "m",
        "(Lcom/google/android/filament/utils/Mat3;)V",
        "",
        "column",
        "get",
        "(I)Lcom/google/android/filament/utils/Float3;",
        "row",
        "",
        "(II)F",
        "Lcom/google/android/filament/utils/MatrixColumn;",
        "(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float3;",
        "(Lcom/google/android/filament/utils/MatrixColumn;I)F",
        "invoke",
        "v",
        "Llx0/b0;",
        "(IIF)V",
        "set",
        "(ILcom/google/android/filament/utils/Float3;)V",
        "unaryMinus",
        "()Lcom/google/android/filament/utils/Mat3;",
        "inc",
        "dec",
        "plus",
        "(F)Lcom/google/android/filament/utils/Mat3;",
        "minus",
        "times",
        "div",
        "delta",
        "compareTo",
        "(FF)Lcom/google/android/filament/utils/Mat3;",
        "",
        "equals",
        "(FF)Z",
        "(Lcom/google/android/filament/utils/Mat3;)Lcom/google/android/filament/utils/Mat3;",
        "(Lcom/google/android/filament/utils/Mat3;F)Lcom/google/android/filament/utils/Mat3;",
        "(Lcom/google/android/filament/utils/Mat3;F)Z",
        "(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;",
        "",
        "toFloatArray",
        "()[F",
        "",
        "toString",
        "()Ljava/lang/String;",
        "component1",
        "()Lcom/google/android/filament/utils/Float3;",
        "component2",
        "component3",
        "copy",
        "(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Mat3;",
        "hashCode",
        "()I",
        "other",
        "(Ljava/lang/Object;)Z",
        "Lcom/google/android/filament/utils/Float3;",
        "getX",
        "setX",
        "(Lcom/google/android/filament/utils/Float3;)V",
        "getY",
        "setY",
        "getZ",
        "setZ",
        "Companion",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lcom/google/android/filament/utils/Mat3$Companion;


# instance fields
.field private x:Lcom/google/android/filament/utils/Float3;

.field private y:Lcom/google/android/filament/utils/Float3;

.field private z:Lcom/google/android/filament/utils/Float3;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/Mat3$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/filament/utils/Mat3;->Companion:Lcom/google/android/filament/utils/Mat3$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 6

    .line 1
    const/4 v4, 0x7

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    const-string v0, "x"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "y"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "z"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    iput-object p2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 5
    iput-object p3, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    return-void
.end method

.method public synthetic constructor <init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;ILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p5, p4, 0x1

    if-eqz p5, :cond_0

    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    const/4 v4, 0x6

    const/4 v5, 0x0

    const/high16 v1, 0x3f800000    # 1.0f

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/utils/Float3;-><init>(FFFILkotlin/jvm/internal/g;)V

    move-object p1, v0

    :cond_0
    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_1

    .line 7
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    const/4 v4, 0x5

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/high16 v2, 0x3f800000    # 1.0f

    const/4 v3, 0x0

    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/utils/Float3;-><init>(FFFILkotlin/jvm/internal/g;)V

    move-object p2, v0

    :cond_1
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_2

    .line 8
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    const/4 v4, 0x3

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/utils/Float3;-><init>(FFFILkotlin/jvm/internal/g;)V

    move-object p3, v0

    .line 9
    :cond_2
    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Mat3;)V
    .locals 8

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    iget-object v1, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    const/4 v5, 0x7

    const/4 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-static/range {v1 .. v6}, Lcom/google/android/filament/utils/Float3;->copy$default(Lcom/google/android/filament/utils/Float3;FFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    iget-object v1, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-static/range {v1 .. v6}, Lcom/google/android/filament/utils/Float3;->copy$default(Lcom/google/android/filament/utils/Float3;FFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    iget-object v2, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    const/4 v6, 0x7

    const/4 v7, 0x0

    const/4 v5, 0x0

    invoke-static/range {v2 .. v7}, Lcom/google/android/filament/utils/Float3;->copy$default(Lcom/google/android/filament/utils/Float3;FFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;

    move-result-object p1

    invoke-direct {p0, v0, v1, p1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-void
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Mat3;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Mat3;
    .locals 6

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 1
    :cond_0
    new-instance p3, Lcom/google/android/filament/utils/Mat3;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    .line 3
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    sub-float v3, v2, p1

    .line 5
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_1

    move v2, p4

    goto :goto_0

    .line 6
    :cond_1
    invoke-static {v2, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 7
    :goto_0
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v3

    sub-float v4, v3, p1

    .line 8
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_2

    move v3, p4

    goto :goto_1

    .line 9
    :cond_2
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 10
    :goto_1
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    sub-float v4, v0, p1

    .line 11
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_3

    move v0, p4

    goto :goto_2

    .line 12
    :cond_3
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 13
    :goto_2
    invoke-direct {v1, v2, v3, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 14
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    .line 15
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 16
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    sub-float v4, v3, p1

    .line 17
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_4

    move v3, p4

    goto :goto_3

    .line 18
    :cond_4
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 19
    :goto_3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    sub-float v5, v4, p1

    .line 20
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_5

    move v4, p4

    goto :goto_4

    .line 21
    :cond_5
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 22
    :goto_4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    sub-float v5, v0, p1

    .line 23
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_6

    move v0, p4

    goto :goto_5

    .line 24
    :cond_6
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 25
    :goto_5
    invoke-direct {v2, v3, v4, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 26
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    .line 27
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 28
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    sub-float v4, v3, p1

    .line 29
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_7

    move v3, p4

    goto :goto_6

    .line 30
    :cond_7
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 31
    :goto_6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    sub-float v5, v4, p1

    .line 32
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_8

    move v4, p4

    goto :goto_7

    .line 33
    :cond_8
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 34
    :goto_7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    sub-float v5, p0, p1

    .line 35
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float p2, v5, p2

    if-gez p2, :cond_9

    goto :goto_8

    .line 36
    :cond_9
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 37
    :goto_8
    invoke-direct {v0, v3, v4, p4}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 38
    invoke-direct {p3, v1, v2, v0}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-object p3
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Mat3;Lcom/google/android/filament/utils/Mat3;FILjava/lang/Object;)Lcom/google/android/filament/utils/Mat3;
    .locals 8

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 39
    :cond_0
    const-string p3, "m"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Mat3;

    .line 40
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    .line 41
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 42
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    sub-float v5, v3, v4

    .line 43
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_1

    move v3, p4

    goto :goto_0

    .line 44
    :cond_1
    invoke-static {v3, v4}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 45
    :goto_0
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    sub-float v6, v4, v5

    .line 46
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_2

    move v4, p4

    goto :goto_1

    .line 47
    :cond_2
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 48
    :goto_1
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    sub-float v5, v0, v1

    .line 49
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_3

    move v0, p4

    goto :goto_2

    .line 50
    :cond_3
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 51
    :goto_2
    invoke-direct {v2, v3, v4, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 52
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    .line 53
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 54
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    sub-float v6, v4, v5

    .line 55
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_4

    move v4, p4

    goto :goto_3

    .line 56
    :cond_4
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 57
    :goto_3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    sub-float v7, v5, v6

    .line 58
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_5

    move v5, p4

    goto :goto_4

    .line 59
    :cond_5
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 60
    :goto_4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    sub-float v6, v0, v1

    .line 61
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_6

    move v0, p4

    goto :goto_5

    .line 62
    :cond_6
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 63
    :goto_5
    invoke-direct {v3, v4, v5, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 64
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p1

    .line 65
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 66
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    sub-float v5, v1, v4

    .line 67
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_7

    move v1, p4

    goto :goto_6

    .line 68
    :cond_7
    invoke-static {v1, v4}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 69
    :goto_6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    sub-float v6, v4, v5

    .line 70
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_8

    move v4, p4

    goto :goto_7

    .line 71
    :cond_8
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 72
    :goto_7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p1

    sub-float v5, p0, p1

    .line 73
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float p2, v5, p2

    if-gez p2, :cond_9

    goto :goto_8

    .line 74
    :cond_9
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 75
    :goto_8
    invoke-direct {v0, v1, v4, p4}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 76
    invoke-direct {p3, v2, v3, v0}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-object p3
.end method

.method public static synthetic copy$default(Lcom/google/android/filament/utils/Mat3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;ILjava/lang/Object;)Lcom/google/android/filament/utils/Mat3;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Mat3;->copy(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Mat3;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Mat3;FFILjava/lang/Object;)Z
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object p3

    .line 2
    invoke-static {p3, p1}, Lc1/j0;->v(Lcom/google/android/filament/utils/Float3;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 3
    invoke-static {p3, p1}, Lc1/j0;->x(Lcom/google/android/filament/utils/Float3;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 4
    invoke-static {p3, p1}, Lc1/j0;->z(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object p3

    .line 6
    invoke-static {p3, p1}, Lc1/j0;->v(Lcom/google/android/filament/utils/Float3;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 7
    invoke-static {p3, p1}, Lc1/j0;->x(Lcom/google/android/filament/utils/Float3;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 8
    invoke-static {p3, p1}, Lc1/j0;->z(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 9
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    .line 10
    invoke-static {p0, p1}, Lc1/j0;->v(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 11
    invoke-static {p0, p1}, Lc1/j0;->x(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 12
    invoke-static {p0, p1}, Lc1/j0;->z(Lcom/google/android/filament/utils/Float3;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Mat3;Lcom/google/android/filament/utils/Mat3;FILjava/lang/Object;)Z
    .locals 1

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 19
    :cond_0
    const-string p3, "m"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object p4

    .line 21
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    .line 22
    invoke-static {p4, v0}, Lc1/j0;->c(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 23
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v0

    .line 24
    invoke-static {p4, v0}, Lc1/j0;->m(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 25
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p3

    .line 26
    invoke-static {p4, p3}, Lc1/j0;->r(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 27
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object p4

    .line 28
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    .line 29
    invoke-static {p4, v0}, Lc1/j0;->c(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 30
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v0

    .line 31
    invoke-static {p4, v0}, Lc1/j0;->m(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 32
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p3

    .line 33
    invoke-static {p4, p3}, Lc1/j0;->r(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 34
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p1

    .line 35
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result p3

    .line 36
    invoke-static {p1, p3}, Lc1/j0;->c(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 37
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result p3

    .line 38
    invoke-static {p1, p3}, Lc1/j0;->m(Lcom/google/android/filament/utils/Float3;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    .line 40
    invoke-static {p1, p0}, Lc1/j0;->r(Lcom/google/android/filament/utils/Float3;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final compareTo(FF)Lcom/google/android/filament/utils/Mat3;
    .locals 8

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    .line 3
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    sub-float v4, v3, p1

    .line 5
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    const/4 v5, 0x0

    if-gez v4, :cond_0

    move v3, v5

    goto :goto_0

    .line 6
    :cond_0
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 7
    :goto_0
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    sub-float v6, v4, p1

    .line 8
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_1

    move v4, v5

    goto :goto_1

    .line 9
    :cond_1
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 10
    :goto_1
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    sub-float v6, v1, p1

    .line 11
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_2

    move v1, v5

    goto :goto_2

    .line 12
    :cond_2
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 13
    :goto_2
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 14
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    .line 15
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 16
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    sub-float v6, v4, p1

    .line 17
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_3

    move v4, v5

    goto :goto_3

    .line 18
    :cond_3
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 19
    :goto_3
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    sub-float v7, v6, p1

    .line 20
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_4

    move v6, v5

    goto :goto_4

    .line 21
    :cond_4
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 22
    :goto_4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    sub-float v7, v1, p1

    .line 23
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_5

    move v1, v5

    goto :goto_5

    .line 24
    :cond_5
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 25
    :goto_5
    invoke-direct {v3, v4, v6, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 26
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    .line 27
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 28
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    sub-float v6, v4, p1

    .line 29
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_6

    move v4, v5

    goto :goto_6

    .line 30
    :cond_6
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 31
    :goto_6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    sub-float v7, v6, p1

    .line 32
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_7

    move v6, v5

    goto :goto_7

    .line 33
    :cond_7
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 34
    :goto_7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    sub-float v7, p0, p1

    .line 35
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float p2, v7, p2

    if-gez p2, :cond_8

    goto :goto_8

    .line 36
    :cond_8
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v5, p0

    .line 37
    :goto_8
    invoke-direct {v1, v4, v6, v5}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 38
    invoke-direct {v0, v2, v3, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-object v0
.end method

.method public final compareTo(Lcom/google/android/filament/utils/Mat3;F)Lcom/google/android/filament/utils/Mat3;
    .locals 10

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 40
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v2

    .line 41
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 42
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    sub-float v6, v4, v5

    .line 43
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    const/4 v7, 0x0

    if-gez v6, :cond_0

    move v4, v7

    goto :goto_0

    .line 44
    :cond_0
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 45
    :goto_0
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    sub-float v8, v5, v6

    .line 46
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_1

    move v5, v7

    goto :goto_1

    .line 47
    :cond_1
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 48
    :goto_1
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v2

    sub-float v6, v1, v2

    .line 49
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_2

    move v1, v7

    goto :goto_2

    .line 50
    :cond_2
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 51
    :goto_2
    invoke-direct {v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 52
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v2

    .line 53
    new-instance v4, Lcom/google/android/filament/utils/Float3;

    .line 54
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v6

    sub-float v8, v5, v6

    .line 55
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_3

    move v5, v7

    goto :goto_3

    .line 56
    :cond_3
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 57
    :goto_3
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v8

    sub-float v9, v6, v8

    .line 58
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_4

    move v6, v7

    goto :goto_4

    .line 59
    :cond_4
    invoke-static {v6, v8}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 60
    :goto_4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v2

    sub-float v8, v1, v2

    .line 61
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_5

    move v1, v7

    goto :goto_5

    .line 62
    :cond_5
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 63
    :goto_5
    invoke-direct {v4, v5, v6, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 64
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p1

    .line 65
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 66
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    sub-float v6, v2, v5

    .line 67
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_6

    move v2, v7

    goto :goto_6

    .line 68
    :cond_6
    invoke-static {v2, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 69
    :goto_6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    sub-float v8, v5, v6

    .line 70
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_7

    move v5, v7

    goto :goto_7

    .line 71
    :cond_7
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 72
    :goto_7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p1

    sub-float v6, p0, p1

    .line 73
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float p2, v6, p2

    if-gez p2, :cond_8

    goto :goto_8

    .line 74
    :cond_8
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v7, p0

    .line 75
    :goto_8
    invoke-direct {v1, v2, v5, v7}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 76
    invoke-direct {v0, v3, v4, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-object v0
.end method

.method public final component1()Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Mat3;
    .locals 0

    .line 1
    const-string p0, "x"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "y"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "z"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lcom/google/android/filament/utils/Mat3;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public final dec()Lcom/google/android/filament/utils/Mat3;
    .locals 5

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->dec()Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iput-object v2, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->dec()Lcom/google/android/filament/utils/Float3;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 18
    .line 19
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->dec()Lcom/google/android/filament/utils/Float3;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    iput-object v4, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    invoke-direct {v0, v1, v2, v3}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public final div(F)Lcom/google/android/filament/utils/Mat3;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    div-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    div-float/2addr v4, p1

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    div-float/2addr v1, p1

    .line 22
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 28
    .line 29
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    div-float/2addr v4, p1

    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    div-float/2addr v5, p1

    .line 39
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    div-float/2addr v1, p1

    .line 44
    invoke-direct {v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 48
    .line 49
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    div-float/2addr v4, p1

    .line 56
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    div-float/2addr v5, p1

    .line 61
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    div-float/2addr p0, p1

    .line 66
    invoke-direct {v1, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 67
    .line 68
    .line 69
    invoke-direct {v0, v2, v3, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 70
    .line 71
    .line 72
    return-object v0
.end method

.method public final equals(FF)Z
    .locals 2

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    .line 3
    invoke-static {v0, p1}, Lc1/j0;->v(Lcom/google/android/filament/utils/Float3;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 4
    invoke-static {v0, p1}, Lc1/j0;->x(Lcom/google/android/filament/utils/Float3;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 5
    invoke-static {v0, p1}, Lc1/j0;->z(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    .line 7
    invoke-static {v0, p1}, Lc1/j0;->v(Lcom/google/android/filament/utils/Float3;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 8
    invoke-static {v0, p1}, Lc1/j0;->x(Lcom/google/android/filament/utils/Float3;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 9
    invoke-static {v0, p1}, Lc1/j0;->z(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    .line 11
    invoke-static {p0, p1}, Lc1/j0;->v(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 12
    invoke-static {p0, p1}, Lc1/j0;->x(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 13
    invoke-static {p0, p1}, Lc1/j0;->z(Lcom/google/android/filament/utils/Float3;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final equals(Lcom/google/android/filament/utils/Mat3;F)Z
    .locals 3

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getX()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    .line 21
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    .line 22
    invoke-static {v1, v2}, Lc1/j0;->c(Lcom/google/android/filament/utils/Float3;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 23
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v2

    .line 24
    invoke-static {v1, v2}, Lc1/j0;->m(Lcom/google/android/filament/utils/Float3;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 25
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    .line 26
    invoke-static {v1, v0}, Lc1/j0;->r(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 27
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getY()Lcom/google/android/filament/utils/Float3;

    move-result-object v1

    .line 28
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    .line 29
    invoke-static {v1, v2}, Lc1/j0;->c(Lcom/google/android/filament/utils/Float3;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 30
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v2

    .line 31
    invoke-static {v1, v2}, Lc1/j0;->m(Lcom/google/android/filament/utils/Float3;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 32
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v0

    .line 33
    invoke-static {v1, v0}, Lc1/j0;->r(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 34
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat3;->getZ()Lcom/google/android/filament/utils/Float3;

    move-result-object p1

    .line 35
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    .line 36
    invoke-static {p1, v0}, Lc1/j0;->c(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 37
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v0

    .line 38
    invoke-static {p1, v0}, Lc1/j0;->m(Lcom/google/android/filament/utils/Float3;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    .line 40
    invoke-static {p1, p0}, Lc1/j0;->r(Lcom/google/android/filament/utils/Float3;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Lcom/google/android/filament/utils/Mat3;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Lcom/google/android/filament/utils/Mat3;

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    return v2

    :cond_2
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    return v2

    :cond_3
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_4

    return v2

    :cond_4
    return v0
.end method

.method public final get(II)F
    .locals 0

    .line 5
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat3;->get(I)Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Float3;->get(I)F

    move-result p0

    return p0
.end method

.method public final get(Lcom/google/android/filament/utils/MatrixColumn;I)F
    .locals 1

    const-string v0, "column"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat3;->get(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Float3;->get(I)F

    move-result p0

    return p0
.end method

.method public final get(I)Lcom/google/android/filament/utils/Float3;
    .locals 1

    if-eqz p1, :cond_2

    const/4 v0, 0x1

    if-eq p1, v0, :cond_1

    const/4 v0, 0x2

    if-ne p1, v0, :cond_0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    return-object p0

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "column must be in 0..2"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 3
    :cond_1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    return-object p0

    .line 4
    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    return-object p0
.end method

.method public final get(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float3;
    .locals 1

    const-string v0, "column"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    sget-object v0, Lcom/google/android/filament/utils/Mat3$WhenMappings;->$EnumSwitchMapping$0:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_2

    const/4 v0, 0x2

    if-eq p1, v0, :cond_1

    const/4 v0, 0x3

    if-ne p1, v0, :cond_0

    .line 7
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    return-object p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "column must be X, Y or Z"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 9
    :cond_1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    return-object p0

    .line 10
    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    return-object p0
.end method

.method public final getX()Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getY()Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getZ()Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 19
    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public final inc()Lcom/google/android/filament/utils/Mat3;
    .locals 5

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->inc()Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iput-object v2, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->inc()Lcom/google/android/filament/utils/Float3;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 18
    .line 19
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->inc()Lcom/google/android/filament/utils/Float3;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    iput-object v4, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    invoke-direct {v0, v1, v2, v3}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public final invoke(II)F
    .locals 0

    add-int/lit8 p2, p2, -0x1

    .line 1
    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Mat3;->get(I)Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float3;->get(I)F

    move-result p0

    return p0
.end method

.method public final invoke(IIF)V
    .locals 0

    add-int/lit8 p2, p2, -0x1

    add-int/lit8 p1, p1, -0x1

    .line 2
    invoke-virtual {p0, p2, p1, p3}, Lcom/google/android/filament/utils/Mat3;->set(IIF)V

    return-void
.end method

.method public final minus(F)Lcom/google/android/filament/utils/Mat3;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    sub-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    sub-float/2addr v4, p1

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    sub-float/2addr v1, p1

    .line 22
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 28
    .line 29
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    sub-float/2addr v4, p1

    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    sub-float/2addr v5, p1

    .line 39
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    sub-float/2addr v1, p1

    .line 44
    invoke-direct {v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 48
    .line 49
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    sub-float/2addr v4, p1

    .line 56
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    sub-float/2addr v5, p1

    .line 61
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    sub-float/2addr p0, p1

    .line 66
    invoke-direct {v1, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 67
    .line 68
    .line 69
    invoke-direct {v0, v2, v3, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 70
    .line 71
    .line 72
    return-object v0
.end method

.method public final plus(F)Lcom/google/android/filament/utils/Mat3;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    add-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    add-float/2addr v4, p1

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    add-float/2addr v1, p1

    .line 22
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 28
    .line 29
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    add-float/2addr v4, p1

    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    add-float/2addr v5, p1

    .line 39
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    add-float/2addr v1, p1

    .line 44
    invoke-direct {v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 48
    .line 49
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    add-float/2addr v4, p1

    .line 56
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    add-float/2addr v5, p1

    .line 61
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    add-float/2addr p0, p1

    .line 66
    invoke-direct {v1, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 67
    .line 68
    .line 69
    invoke-direct {v0, v2, v3, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 70
    .line 71
    .line 72
    return-object v0
.end method

.method public final set(IIF)V
    .locals 0

    .line 5
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat3;->get(I)Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    invoke-virtual {p0, p2, p3}, Lcom/google/android/filament/utils/Float3;->set(IF)V

    return-void
.end method

.method public final set(ILcom/google/android/filament/utils/Float3;)V
    .locals 1

    const-string v0, "v"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat3;->get(I)Lcom/google/android/filament/utils/Float3;

    move-result-object p0

    .line 2
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float3;->setX(F)V

    .line 3
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float3;->setY(F)V

    .line 4
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float3;->setZ(F)V

    return-void
.end method

.method public final setX(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 7
    .line 8
    return-void
.end method

.method public final setY(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 7
    .line 8
    return-void
.end method

.method public final setZ(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 7
    .line 8
    return-void
.end method

.method public final times(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;
    .locals 5

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 71
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v1

    .line 72
    invoke-static {p1, v1, v2}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v1

    .line 73
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    .line 74
    invoke-static {p1, v2, v1}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v1

    .line 75
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    mul-float/2addr v3, v2

    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v2

    .line 76
    invoke-static {p1, v2, v3}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v2

    .line 77
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v3

    .line 78
    invoke-static {p1, v3, v2}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v2

    .line 79
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v3

    .line 80
    invoke-static {p1, v3, v4}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v3

    .line 81
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    .line 82
    invoke-static {p1, p0, v3}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result p0

    .line 83
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    return-object v0
.end method

.method public final times(F)Lcom/google/android/filament/utils/Mat3;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 2
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    mul-float/2addr v3, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    mul-float/2addr v4, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 4
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    mul-float/2addr v4, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    mul-float/2addr v5, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-direct {v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 5
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 6
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    mul-float/2addr v4, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    mul-float/2addr v5, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    mul-float/2addr p0, p1

    invoke-direct {v1, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 7
    invoke-direct {v0, v2, v3, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-object v0
.end method

.method public final times(Lcom/google/android/filament/utils/Mat3;)Lcom/google/android/filament/utils/Mat3;
    .locals 9

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 9
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 10
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    mul-float/2addr v3, v2

    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v2

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 11
    invoke-static {v4, v2, v3}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v2

    .line 12
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 13
    invoke-static {v4, v3, v2}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v2

    .line 14
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v3

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 15
    invoke-static {v5, v3, v4}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v3

    .line 16
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 17
    invoke-static {v5, v4, v3}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v3

    .line 18
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v4

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 19
    invoke-static {v6, v4, v5}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v4

    .line 20
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 21
    invoke-static {v6, v5, v4}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v4

    .line 22
    invoke-direct {v1, v2, v3, v4}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 23
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 24
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v3

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 25
    invoke-static {v5, v3, v4}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v3

    .line 26
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 27
    invoke-static {v5, v4, v3}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v3

    .line 28
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v4

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 29
    invoke-static {v6, v4, v5}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v4

    .line 30
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 31
    invoke-static {v6, v5, v4}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v4

    .line 32
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v6

    mul-float/2addr v6, v5

    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v5

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 33
    invoke-static {v7, v5, v6}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v5

    .line 34
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 35
    invoke-static {v7, v6, v5}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v5

    .line 36
    invoke-direct {v2, v3, v4, v5}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 37
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 38
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v4

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 39
    invoke-static {v6, v4, v5}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v4

    .line 40
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 41
    invoke-static {v6, v5, v4}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v4

    .line 42
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v6

    mul-float/2addr v6, v5

    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v5

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 43
    invoke-static {v7, v5, v6}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v5

    .line 44
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 45
    invoke-static {v7, v6, v5}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v5

    .line 46
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v7

    mul-float/2addr v7, v6

    iget-object v6, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result v6

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 47
    invoke-static {v8, v6, v7}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    move-result v6

    .line 48
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p0

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 49
    invoke-static {p1, p0, v6}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    move-result p0

    .line 50
    invoke-direct {v3, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 51
    invoke-direct {v0, v1, v2, v3}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-object v0
.end method

.method public final toFloatArray()[F
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 14
    .line 15
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 32
    .line 33
    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 38
    .line 39
    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 44
    .line 45
    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    const/16 v8, 0x9

    .line 56
    .line 57
    new-array v8, v8, [F

    .line 58
    .line 59
    const/4 v9, 0x0

    .line 60
    aput v0, v8, v9

    .line 61
    .line 62
    const/4 v0, 0x1

    .line 63
    aput v1, v8, v0

    .line 64
    .line 65
    const/4 v0, 0x2

    .line 66
    aput v2, v8, v0

    .line 67
    .line 68
    const/4 v0, 0x3

    .line 69
    aput v3, v8, v0

    .line 70
    .line 71
    const/4 v0, 0x4

    .line 72
    aput v4, v8, v0

    .line 73
    .line 74
    const/4 v0, 0x5

    .line 75
    aput v5, v8, v0

    .line 76
    .line 77
    const/4 v0, 0x6

    .line 78
    aput v6, v8, v0

    .line 79
    .line 80
    const/4 v0, 0x7

    .line 81
    aput v7, v8, v0

    .line 82
    .line 83
    const/16 v0, 0x8

    .line 84
    .line 85
    aput p0, v8, v0

    .line 86
    .line 87
    return-object v8
.end method

.method public toString()Ljava/lang/String;
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 14
    .line 15
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 26
    .line 27
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 32
    .line 33
    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 38
    .line 39
    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 44
    .line 45
    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    new-instance v8, Ljava/lang/StringBuilder;

    .line 56
    .line 57
    const-string v9, "\n            |"

    .line 58
    .line 59
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string v0, " "

    .line 66
    .line 67
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    const-string v1, "|\n            |"

    .line 80
    .line 81
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v8, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string p0, "|\n            "

    .line 118
    .line 119
    invoke-virtual {v8, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-static {p0}, Lly0/q;->g(Ljava/lang/String;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0
.end method

.method public final unaryMinus()Lcom/google/android/filament/utils/Mat3;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat3;->x:Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->unaryMinus()Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat3;->y:Lcom/google/android/filament/utils/Float3;

    .line 10
    .line 11
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->unaryMinus()Lcom/google/android/filament/utils/Float3;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat3;->z:Lcom/google/android/filament/utils/Float3;

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->unaryMinus()Lcom/google/android/filament/utils/Float3;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method
