.class public final Lcom/google/android/filament/utils/Quaternion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Quaternion$Companion;,
        Lcom/google/android/filament/utils/Quaternion$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000h\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0013\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0014\n\u0002\u0008\t\n\u0002\u0010\u000e\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u001c\u0008\u0086\u0008\u0018\u0000 n2\u00020\u0001:\u0001nB/\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u0008B\u001b\u0008\u0016\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u000bB\u0011\u0008\u0016\u0012\u0006\u0010\n\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\u0007\u0010\rB\u0011\u0008\u0016\u0012\u0006\u0010\u000e\u001a\u00020\u0000\u00a2\u0006\u0004\u0008\u0007\u0010\u000fJ\u0018\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0011\u001a\u00020\u0010H\u0086\u0002\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J(\u0010\u0012\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u0010H\u0086\u0002\u00a2\u0006\u0004\u0008\u0012\u0010\u0017J0\u0010\u0012\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u00102\u0006\u0010\u0018\u001a\u00020\u0010H\u0086\u0002\u00a2\u0006\u0004\u0008\u0012\u0010\u0019J\u0018\u0010\u0012\u001a\u00020\u00022\u0006\u0010\u0011\u001a\u00020\u001aH\u0086\u0002\u00a2\u0006\u0004\u0008\u0012\u0010\u001bJ(\u0010\u0012\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\u001a2\u0006\u0010\u0015\u001a\u00020\u001a2\u0006\u0010\u0016\u001a\u00020\u001aH\u0086\u0002\u00a2\u0006\u0004\u0008\u0012\u0010\u001cJ0\u0010\u0012\u001a\u00020\u00002\u0006\u0010\u0014\u001a\u00020\u001a2\u0006\u0010\u0015\u001a\u00020\u001a2\u0006\u0010\u0016\u001a\u00020\u001a2\u0006\u0010\u0018\u001a\u00020\u001aH\u0086\u0002\u00a2\u0006\u0004\u0008\u0012\u0010\u001dJ\u0018\u0010\u001e\u001a\u00020\u00022\u0006\u0010\u0011\u001a\u00020\u001aH\u0086\n\u00a2\u0006\u0004\u0008\u001e\u0010\u001bJ \u0010 \u001a\u00020\u001f2\u0006\u0010\u0011\u001a\u00020\u001a2\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010!J(\u0010 \u001a\u00020\u001f2\u0006\u0010\u0014\u001a\u00020\u001a2\u0006\u0010\u0015\u001a\u00020\u001a2\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010\"J0\u0010 \u001a\u00020\u001f2\u0006\u0010\u0014\u001a\u00020\u001a2\u0006\u0010\u0015\u001a\u00020\u001a2\u0006\u0010\u0016\u001a\u00020\u001a2\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010#J8\u0010 \u001a\u00020\u001f2\u0006\u0010\u0014\u001a\u00020\u001a2\u0006\u0010\u0015\u001a\u00020\u001a2\u0006\u0010\u0016\u001a\u00020\u001a2\u0006\u0010\u0018\u001a\u00020\u001a2\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010$J \u0010 \u001a\u00020\u001f2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010%J(\u0010 \u001a\u00020\u001f2\u0006\u0010\u0014\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010&J0\u0010 \u001a\u00020\u001f2\u0006\u0010\u0014\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010\'J8\u0010 \u001a\u00020\u001f2\u0006\u0010\u0014\u001a\u00020\u00102\u0006\u0010\u0015\u001a\u00020\u00102\u0006\u0010\u0016\u001a\u00020\u00102\u0006\u0010\u0018\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008 \u0010(J\u0010\u0010)\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008)\u0010*J\u0018\u0010+\u001a\u00020\u00002\u0006\u0010\n\u001a\u00020\u0002H\u0086\n\u00a2\u0006\u0004\u0008+\u0010,J\u0018\u0010-\u001a\u00020\u00002\u0006\u0010\n\u001a\u00020\u0002H\u0086\n\u00a2\u0006\u0004\u0008-\u0010,J\u0018\u0010.\u001a\u00020\u00002\u0006\u0010\n\u001a\u00020\u0002H\u0086\n\u00a2\u0006\u0004\u0008.\u0010,J\u0018\u0010/\u001a\u00020\u00002\u0006\u0010\n\u001a\u00020\u0002H\u0086\n\u00a2\u0006\u0004\u0008/\u0010,J\"\u00101\u001a\u00020\u000c2\u0006\u0010\n\u001a\u00020\u00022\u0008\u0008\u0002\u00100\u001a\u00020\u0002H\u0086\u0008\u00a2\u0006\u0004\u00081\u00102J\"\u00104\u001a\u0002032\u0006\u0010\n\u001a\u00020\u00022\u0008\u0008\u0002\u00100\u001a\u00020\u0002H\u0086\u0008\u00a2\u0006\u0004\u00084\u00105J\u0018\u0010.\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\tH\u0086\n\u00a2\u0006\u0004\u0008.\u00106J\u0018\u0010+\u001a\u00020\u00002\u0006\u0010\u000e\u001a\u00020\u0000H\u0086\n\u00a2\u0006\u0004\u0008+\u00107J\u0018\u0010-\u001a\u00020\u00002\u0006\u0010\u000e\u001a\u00020\u0000H\u0086\n\u00a2\u0006\u0004\u0008-\u00107J\u0018\u0010.\u001a\u00020\u00002\u0006\u0010\u000e\u001a\u00020\u0000H\u0086\n\u00a2\u0006\u0004\u0008.\u00107J\"\u00101\u001a\u00020\u000c2\u0006\u0010\n\u001a\u00020\u000c2\u0008\u0008\u0002\u00100\u001a\u00020\u0002H\u0086\u0008\u00a2\u0006\u0004\u00081\u00108J\"\u00104\u001a\u0002032\u0006\u0010\n\u001a\u00020\u000c2\u0008\u0008\u0002\u00100\u001a\u00020\u0002H\u0086\u0008\u00a2\u0006\u0004\u00084\u00109J\'\u0010<\u001a\u00020\u00002\u0012\u0010;\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020:H\u0086\u0008\u00f8\u0001\u0000\u00a2\u0006\u0004\u0008<\u0010=J\r\u0010>\u001a\u00020\t\u00a2\u0006\u0004\u0008>\u0010?J\r\u0010A\u001a\u00020@\u00a2\u0006\u0004\u0008A\u0010BJ\r\u0010D\u001a\u00020C\u00a2\u0006\u0004\u0008D\u0010EJ\u0010\u0010F\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008F\u0010GJ\u0010\u0010H\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008H\u0010GJ\u0010\u0010I\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008I\u0010GJ\u0010\u0010J\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008J\u0010GJ8\u0010K\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u0008K\u0010LJ\u0010\u0010N\u001a\u00020MH\u00d6\u0001\u00a2\u0006\u0004\u0008N\u0010OJ\u0010\u0010P\u001a\u00020\u001aH\u00d6\u0001\u00a2\u0006\u0004\u0008P\u0010QJ\u001a\u00104\u001a\u00020S2\u0008\u0010R\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u00084\u0010TR\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010U\u001a\u0004\u0008V\u0010G\"\u0004\u0008W\u0010XR\"\u0010\u0004\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010U\u001a\u0004\u0008Y\u0010G\"\u0004\u0008Z\u0010XR\"\u0010\u0005\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0005\u0010U\u001a\u0004\u0008[\u0010G\"\u0004\u0008\\\u0010XR\"\u0010\u0006\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0006\u0010U\u001a\u0004\u0008]\u0010G\"\u0004\u0008^\u0010XR&\u0010c\u001a\u00020\t2\u0006\u0010_\u001a\u00020\t8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008`\u0010?\"\u0004\u0008a\u0010bR&\u0010f\u001a\u00020\t2\u0006\u0010_\u001a\u00020\t8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008d\u0010?\"\u0004\u0008e\u0010bR&\u0010i\u001a\u00020\u00022\u0006\u0010_\u001a\u00020\u00028\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008g\u0010G\"\u0004\u0008h\u0010XR&\u0010m\u001a\u00020\u000c2\u0006\u0010_\u001a\u00020\u000c8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008j\u0010k\"\u0004\u0008l\u0010\r\u0082\u0002\u0007\n\u0005\u0008\u009920\u0001\u00a8\u0006o"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Quaternion;",
        "",
        "",
        "x",
        "y",
        "z",
        "w",
        "<init>",
        "(FFFF)V",
        "Lcom/google/android/filament/utils/Float3;",
        "v",
        "(Lcom/google/android/filament/utils/Float3;F)V",
        "Lcom/google/android/filament/utils/Float4;",
        "(Lcom/google/android/filament/utils/Float4;)V",
        "q",
        "(Lcom/google/android/filament/utils/Quaternion;)V",
        "Lcom/google/android/filament/utils/QuaternionComponent;",
        "index",
        "get",
        "(Lcom/google/android/filament/utils/QuaternionComponent;)F",
        "index1",
        "index2",
        "index3",
        "(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;)Lcom/google/android/filament/utils/Float3;",
        "index4",
        "(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;)Lcom/google/android/filament/utils/Quaternion;",
        "",
        "(I)F",
        "(III)Lcom/google/android/filament/utils/Float3;",
        "(IIII)Lcom/google/android/filament/utils/Quaternion;",
        "invoke",
        "Llx0/b0;",
        "set",
        "(IF)V",
        "(IIF)V",
        "(IIIF)V",
        "(IIIIF)V",
        "(Lcom/google/android/filament/utils/QuaternionComponent;F)V",
        "(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;F)V",
        "(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;F)V",
        "(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;F)V",
        "unaryMinus",
        "()Lcom/google/android/filament/utils/Quaternion;",
        "plus",
        "(F)Lcom/google/android/filament/utils/Quaternion;",
        "minus",
        "times",
        "div",
        "delta",
        "compareTo",
        "(FF)Lcom/google/android/filament/utils/Float4;",
        "Lcom/google/android/filament/utils/Bool4;",
        "equals",
        "(FF)Lcom/google/android/filament/utils/Bool4;",
        "(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;",
        "(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;",
        "(Lcom/google/android/filament/utils/Float4;F)Lcom/google/android/filament/utils/Float4;",
        "(Lcom/google/android/filament/utils/Float4;F)Lcom/google/android/filament/utils/Bool4;",
        "Lkotlin/Function1;",
        "block",
        "transform",
        "(Lay0/k;)Lcom/google/android/filament/utils/Quaternion;",
        "toEulerAngles",
        "()Lcom/google/android/filament/utils/Float3;",
        "Lcom/google/android/filament/utils/Mat4;",
        "toMatrix",
        "()Lcom/google/android/filament/utils/Mat4;",
        "",
        "toFloatArray",
        "()[F",
        "component1",
        "()F",
        "component2",
        "component3",
        "component4",
        "copy",
        "(FFFF)Lcom/google/android/filament/utils/Quaternion;",
        "",
        "toString",
        "()Ljava/lang/String;",
        "hashCode",
        "()I",
        "other",
        "",
        "(Ljava/lang/Object;)Z",
        "F",
        "getX",
        "setX",
        "(F)V",
        "getY",
        "setY",
        "getZ",
        "setZ",
        "getW",
        "setW",
        "value",
        "getXyz",
        "setXyz",
        "(Lcom/google/android/filament/utils/Float3;)V",
        "xyz",
        "getImaginary",
        "setImaginary",
        "imaginary",
        "getReal",
        "setReal",
        "real",
        "getXyzw",
        "()Lcom/google/android/filament/utils/Float4;",
        "setXyzw",
        "xyzw",
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
.field public static final Companion:Lcom/google/android/filament/utils/Quaternion$Companion;


# instance fields
.field private w:F

.field private x:F

.field private y:F

.field private z:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Quaternion$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/Quaternion$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/filament/utils/Quaternion;->Companion:Lcom/google/android/filament/utils/Quaternion$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 7

    .line 1
    const/16 v5, 0xf

    const/4 v6, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFFILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(FFFF)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 4
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 5
    iput p3, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 6
    iput p4, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    return-void
.end method

.method public synthetic constructor <init>(FFFFILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x1

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    const/high16 p4, 0x3f800000    # 1.0f

    .line 7
    :cond_3
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float3;F)V
    .locals 2

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p1

    invoke-direct {p0, v0, v1, p1, p2}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-void
.end method

.method public synthetic constructor <init>(Lcom/google/android/filament/utils/Float3;FILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/high16 p2, 0x3f800000    # 1.0f

    .line 9
    :cond_0
    invoke-direct {p0, p1, p2}, Lcom/google/android/filament/utils/Quaternion;-><init>(Lcom/google/android/filament/utils/Float3;F)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float4;)V
    .locals 3

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    invoke-direct {p0, v0, v1, v2, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Quaternion;)V
    .locals 3

    const-string v0, "q"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    iget v0, p1, Lcom/google/android/filament/utils/Quaternion;->x:F

    iget v1, p1, Lcom/google/android/filament/utils/Quaternion;->y:F

    iget v2, p1, Lcom/google/android/filament/utils/Quaternion;->z:F

    iget p1, p1, Lcom/google/android/filament/utils/Quaternion;->w:F

    invoke-direct {p0, v0, v1, v2, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-void
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Quaternion;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Float4;
    .locals 4

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 1
    :cond_0
    new-instance p3, Lcom/google/android/filament/utils/Float4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v0

    sub-float v1, v0, p1

    .line 3
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_1

    move v0, p4

    goto :goto_0

    .line 4
    :cond_1
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 5
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    sub-float v2, v1, p1

    .line 6
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v1, p4

    goto :goto_1

    .line 7
    :cond_2
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 8
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v2

    sub-float v3, v2, p1

    .line 9
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v2, p4

    goto :goto_2

    .line 10
    :cond_3
    invoke-static {v2, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 11
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float v3, p0, p1

    .line 12
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float p2, v3, p2

    if-gez p2, :cond_4

    goto :goto_3

    .line 13
    :cond_4
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 14
    :goto_3
    invoke-direct {p3, v0, v1, v2, p4}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    return-object p3
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;FILjava/lang/Object;)Lcom/google/android/filament/utils/Float4;
    .locals 5

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 15
    :cond_0
    const-string p3, "v"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Float4;

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v1

    sub-float v2, v0, v1

    .line 17
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_1

    move v0, p4

    goto :goto_0

    .line 18
    :cond_1
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 19
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v2

    sub-float v3, v1, v2

    .line 20
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_2

    move v1, p4

    goto :goto_1

    .line 21
    :cond_2
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 22
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v3

    sub-float v4, v2, v3

    .line 23
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_3

    move v2, p4

    goto :goto_2

    .line 24
    :cond_3
    invoke-static {v2, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 25
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    sub-float v3, p0, p1

    .line 26
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float p2, v3, p2

    if-gez p2, :cond_4

    goto :goto_3

    .line 27
    :cond_4
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 28
    :goto_3
    invoke-direct {p3, v0, v1, v2, p4}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    return-object p3
.end method

.method public static synthetic copy$default(Lcom/google/android/filament/utils/Quaternion;FFFFILjava/lang/Object;)Lcom/google/android/filament/utils/Quaternion;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget p3, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget p4, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Quaternion;->copy(FFFF)Lcom/google/android/filament/utils/Quaternion;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Quaternion;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Bool4;
    .locals 4

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    new-instance p3, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p4

    sub-float/2addr p4, p1

    .line 3
    invoke-static {p4}, Ljava/lang/Math;->abs(F)F

    move-result p4

    cmpg-float p4, p4, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-gez p4, :cond_1

    move p4, v1

    goto :goto_0

    :cond_1
    move p4, v0

    .line 4
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    sub-float/2addr v2, p1

    .line 5
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v2, v1

    goto :goto_1

    :cond_2
    move v2, v0

    .line 6
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    sub-float/2addr v3, p1

    .line 7
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v0

    .line 8
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    .line 9
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_4

    move v0, v1

    .line 10
    :cond_4
    invoke-direct {p3, p4, v2, v3, v0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object p3
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;FILjava/lang/Object;)Lcom/google/android/filament/utils/Bool4;
    .locals 4

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 11
    :cond_0
    const-string p3, "v"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Bool4;

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p4

    .line 13
    invoke-static {p1, p4}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-gez p4, :cond_1

    move p4, v1

    goto :goto_0

    :cond_1
    move p4, v0

    .line 14
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    .line 15
    invoke-static {p1, v2}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v2, v1

    goto :goto_1

    :cond_2
    move v2, v0

    .line 16
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    .line 17
    invoke-static {p1, v3}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v0

    .line 18
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    .line 19
    invoke-static {p1, p0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_4

    move v0, v1

    .line 20
    :cond_4
    invoke-direct {p3, p4, v2, v3, v0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object p3
.end method


# virtual methods
.method public final compareTo(FF)Lcom/google/android/filament/utils/Float4;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    sub-float v2, v1, p1

    .line 3
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    const/4 v3, 0x0

    if-gez v2, :cond_0

    move v1, v3

    goto :goto_0

    .line 4
    :cond_0
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 5
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    sub-float v4, v2, p1

    .line 6
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v2, v3

    goto :goto_1

    .line 7
    :cond_1
    invoke-static {v2, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 8
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    sub-float v5, v4, p1

    .line 9
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v4, v3

    goto :goto_2

    .line 10
    :cond_2
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 11
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float v5, p0, p1

    .line 12
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float p2, v5, p2

    if-gez p2, :cond_3

    goto :goto_3

    .line 13
    :cond_3
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v3, p0

    .line 14
    :goto_3
    invoke-direct {v0, v1, v2, v4, v3}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    return-object v0
.end method

.method public final compareTo(Lcom/google/android/filament/utils/Float4;F)Lcom/google/android/filament/utils/Float4;
    .locals 7

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    sub-float v3, v1, v2

    .line 17
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    const/4 v4, 0x0

    if-gez v3, :cond_0

    move v1, v4

    goto :goto_0

    .line 18
    :cond_0
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 19
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v3

    sub-float v5, v2, v3

    .line 20
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_1

    move v2, v4

    goto :goto_1

    .line 21
    :cond_1
    invoke-static {v2, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 22
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    sub-float v6, v3, v5

    .line 23
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_2

    move v3, v4

    goto :goto_2

    .line 24
    :cond_2
    invoke-static {v3, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 25
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    sub-float v5, p0, p1

    .line 26
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float p2, v5, p2

    if-gez p2, :cond_3

    goto :goto_3

    .line 27
    :cond_3
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v4, p0

    .line 28
    :goto_3
    invoke-direct {v0, v1, v2, v3, v4}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    return-object v0
.end method

.method public final component1()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 2
    .line 3
    return p0
.end method

.method public final component2()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 2
    .line 3
    return p0
.end method

.method public final component3()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 2
    .line 3
    return p0
.end method

.method public final component4()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 2
    .line 3
    return p0
.end method

.method public final copy(FFFF)Lcom/google/android/filament/utils/Quaternion;
    .locals 0

    .line 1
    new-instance p0, Lcom/google/android/filament/utils/Quaternion;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final div(F)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    div-float/2addr v1, p1

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    div-float/2addr v2, p1

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    div-float/2addr v3, p1

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    div-float/2addr p0, p1

    .line 23
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public final equals(FF)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    sub-float/2addr v1, p1

    .line 4
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 5
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    sub-float/2addr v4, p1

    .line 6
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 7
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    sub-float/2addr v5, p1

    .line 8
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 9
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    .line 10
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_3

    move v2, v3

    .line 11
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public final equals(Lcom/google/android/filament/utils/Float4;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    .line 14
    invoke-static {p1, v1}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 15
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    .line 16
    invoke-static {p1, v4}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 17
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    .line 18
    invoke-static {p1, v5}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 19
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    .line 20
    invoke-static {p1, p0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_3

    move v2, v3

    .line 21
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Lcom/google/android/filament/utils/Quaternion;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Lcom/google/android/filament/utils/Quaternion;

    iget v1, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    iget v3, p1, Lcom/google/android/filament/utils/Quaternion;->x:F

    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    if-eqz v1, :cond_2

    return v2

    :cond_2
    iget v1, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    iget v3, p1, Lcom/google/android/filament/utils/Quaternion;->y:F

    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    if-eqz v1, :cond_3

    return v2

    :cond_3
    iget v1, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    iget v3, p1, Lcom/google/android/filament/utils/Quaternion;->z:F

    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    if-eqz v1, :cond_4

    return v2

    :cond_4
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    iget p1, p1, Lcom/google/android/filament/utils/Quaternion;->w:F

    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    if-eqz p0, :cond_5

    return v2

    :cond_5
    return v0
.end method

.method public final get(I)F
    .locals 1

    if-eqz p1, :cond_3

    const/4 v0, 0x1

    if-eq p1, v0, :cond_2

    const/4 v0, 0x2

    if-eq p1, v0, :cond_1

    const/4 v0, 0x3

    if-ne p1, v0, :cond_0

    .line 11
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    return p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "index must be in 0..3"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 13
    :cond_1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    return p0

    .line 14
    :cond_2
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    return p0

    .line 15
    :cond_3
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    return p0
.end method

.method public final get(Lcom/google/android/filament/utils/QuaternionComponent;)F
    .locals 1

    const-string v0, "index"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    sget-object v0, Lcom/google/android/filament/utils/Quaternion$WhenMappings;->$EnumSwitchMapping$0:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_3

    const/4 v0, 0x2

    if-eq p1, v0, :cond_2

    const/4 v0, 0x3

    if-eq p1, v0, :cond_1

    const/4 v0, 0x4

    if-ne p1, v0, :cond_0

    .line 2
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    return p0

    .line 3
    :cond_0
    new-instance p0, La8/r0;

    .line 4
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 5
    throw p0

    .line 6
    :cond_1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    return p0

    .line 7
    :cond_2
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    return p0

    .line 8
    :cond_3
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    return p0
.end method

.method public final get(III)Lcom/google/android/filament/utils/Float3;
    .locals 1

    .line 16
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p1

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p2

    invoke-virtual {p0, p3}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p0

    invoke-direct {v0, p1, p2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    return-object v0
.end method

.method public final get(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;)Lcom/google/android/filament/utils/Float3;
    .locals 1

    const-string v0, "index1"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index2"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index3"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p1

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p2

    invoke-virtual {p0, p3}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p0

    invoke-direct {v0, p1, p2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    return-object v0
.end method

.method public final get(IIII)Lcom/google/android/filament/utils/Quaternion;
    .locals 1

    .line 17
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p1

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p2

    invoke-virtual {p0, p3}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p3

    invoke-virtual {p0, p4}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    move-result p0

    invoke-direct {v0, p1, p2, p3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final get(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;)Lcom/google/android/filament/utils/Quaternion;
    .locals 1

    const-string v0, "index1"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index2"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index3"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index4"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p1

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p2

    invoke-virtual {p0, p3}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p3

    invoke-virtual {p0, p4}, Lcom/google/android/filament/utils/Quaternion;->get(Lcom/google/android/filament/utils/QuaternionComponent;)F

    move-result p0

    invoke-direct {v0, p1, p2, p3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final getImaginary()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final getReal()F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getW()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 2
    .line 3
    return p0
.end method

.method public final getX()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 2
    .line 3
    return p0
.end method

.method public final getXyz()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final getXyzw()Lcom/google/android/filament/utils/Float4;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final getY()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 2
    .line 3
    return p0
.end method

.method public final getZ()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 23
    .line 24
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public final invoke(I)F
    .locals 0

    .line 1
    add-int/lit8 p1, p1, -0x1

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->get(I)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final minus(F)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    sub-float/2addr v1, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    sub-float/2addr v2, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    sub-float/2addr v3, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final minus(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 5

    const-string v0, "q"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    sub-float/2addr v1, v2

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    sub-float/2addr v2, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    sub-float/2addr v3, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    sub-float/2addr p0, p1

    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final plus(F)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    add-float/2addr v1, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    add-float/2addr v2, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    add-float/2addr v3, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    add-float/2addr p0, p1

    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final plus(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 5

    const-string v0, "q"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    add-float/2addr v2, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    add-float/2addr v3, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    add-float/2addr v4, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    add-float/2addr p1, p0

    invoke-direct {v0, v2, v3, v4, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final set(IF)V
    .locals 1

    if-eqz p1, :cond_3

    const/4 v0, 0x1

    if-eq p1, v0, :cond_2

    const/4 v0, 0x2

    if-eq p1, v0, :cond_1

    const/4 v0, 0x3

    if-ne p1, v0, :cond_0

    .line 1
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    return-void

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "index must be in 0..3"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 3
    :cond_1
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    return-void

    .line 4
    :cond_2
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    return-void

    .line 5
    :cond_3
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    return-void
.end method

.method public final set(IIF)V
    .locals 0

    .line 6
    invoke-virtual {p0, p1, p3}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    .line 7
    invoke-virtual {p0, p2, p3}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    return-void
.end method

.method public final set(IIIF)V
    .locals 0

    .line 8
    invoke-virtual {p0, p1, p4}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    .line 9
    invoke-virtual {p0, p2, p4}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    .line 10
    invoke-virtual {p0, p3, p4}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    return-void
.end method

.method public final set(IIIIF)V
    .locals 0

    .line 11
    invoke-virtual {p0, p1, p5}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    .line 12
    invoke-virtual {p0, p2, p5}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    .line 13
    invoke-virtual {p0, p3, p5}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    .line 14
    invoke-virtual {p0, p4, p5}, Lcom/google/android/filament/utils/Quaternion;->set(IF)V

    return-void
.end method

.method public final set(Lcom/google/android/filament/utils/QuaternionComponent;F)V
    .locals 1

    const-string v0, "index"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    sget-object v0, Lcom/google/android/filament/utils/Quaternion$WhenMappings;->$EnumSwitchMapping$0:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_3

    const/4 v0, 0x2

    if-eq p1, v0, :cond_2

    const/4 v0, 0x3

    if-eq p1, v0, :cond_1

    const/4 v0, 0x4

    if-ne p1, v0, :cond_0

    .line 16
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    return-void

    .line 17
    :cond_0
    new-instance p0, La8/r0;

    .line 18
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 19
    throw p0

    .line 20
    :cond_1
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    return-void

    .line 21
    :cond_2
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    return-void

    .line 22
    :cond_3
    iput p2, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    return-void
.end method

.method public final set(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;F)V
    .locals 1

    const-string v0, "index1"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index2"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    invoke-virtual {p0, p1, p3}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    .line 24
    invoke-virtual {p0, p2, p3}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    return-void
.end method

.method public final set(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;F)V
    .locals 1

    const-string v0, "index1"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index2"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index3"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    invoke-virtual {p0, p1, p4}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    .line 26
    invoke-virtual {p0, p2, p4}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    .line 27
    invoke-virtual {p0, p3, p4}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    return-void
.end method

.method public final set(Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;Lcom/google/android/filament/utils/QuaternionComponent;F)V
    .locals 1

    const-string v0, "index1"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index2"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index3"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "index4"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    invoke-virtual {p0, p1, p5}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    .line 29
    invoke-virtual {p0, p2, p5}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    .line 30
    invoke-virtual {p0, p3, p5}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    .line 31
    invoke-virtual {p0, p4, p5}, Lcom/google/android/filament/utils/Quaternion;->set(Lcom/google/android/filament/utils/QuaternionComponent;F)V

    return-void
.end method

.method public final setImaginary(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setX(F)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setY(F)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->setZ(F)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final setReal(F)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->setW(F)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final setW(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 2
    .line 3
    return-void
.end method

.method public final setX(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 2
    .line 3
    return-void
.end method

.method public final setXyz(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setX(F)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setY(F)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->setZ(F)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final setXyzw(Lcom/google/android/filament/utils/Float4;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setX(F)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setY(F)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setZ(F)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->setW(F)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final setY(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 2
    .line 3
    return-void
.end method

.method public final setZ(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 2
    .line 3
    return-void
.end method

.method public final times(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;
    .locals 7

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Lcom/google/android/filament/utils/Quaternion;-><init>(Lcom/google/android/filament/utils/Float3;F)V

    .line 3
    new-instance p1, Lcom/google/android/filament/utils/Quaternion;

    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v2

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v2

    mul-float/2addr v2, v1

    add-float/2addr v2, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    sub-float/2addr v2, v3

    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    mul-float/2addr v4, v1

    sub-float/2addr v3, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v4

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    mul-float/2addr v4, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    mul-float/2addr v5, v1

    add-float/2addr v5, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v4

    mul-float/2addr v4, v1

    sub-float/2addr v5, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v5

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v5

    mul-float/2addr v5, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v6

    mul-float/2addr v6, v1

    sub-float/2addr v5, v6

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v6

    mul-float/2addr v6, v1

    sub-float/2addr v5, v6

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v0

    mul-float/2addr v0, v1

    sub-float/2addr v5, v0

    .line 8
    invoke-direct {p1, v2, v3, v4, v5}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 9
    invoke-static {p0}, Lcom/google/android/filament/utils/QuaternionKt;->inverse(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;

    move-result-object p0

    .line 10
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 11
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v2

    mul-float/2addr v2, v1

    add-float/2addr v2, v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    sub-float/2addr v2, v3

    .line 12
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    mul-float/2addr v4, v1

    sub-float/2addr v3, v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v4

    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    mul-float/2addr v4, v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    mul-float/2addr v5, v1

    add-float/2addr v5, v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v4

    mul-float/2addr v4, v1

    sub-float/2addr v5, v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v5

    .line 14
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v5

    mul-float/2addr v5, v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v6

    mul-float/2addr v6, v1

    sub-float/2addr v5, v6

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v6

    mul-float/2addr v6, v1

    sub-float/2addr v5, v6

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result p0

    mul-float/2addr p0, p1

    sub-float/2addr v5, p0

    .line 15
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 16
    new-instance p0, Lcom/google/android/filament/utils/Float3;

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v0

    invoke-direct {p0, p1, v1, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    return-object p0
.end method

.method public final times(F)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    mul-float/2addr v2, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    mul-float/2addr v3, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    mul-float/2addr p0, p1

    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final times(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 7

    const-string v0, "q"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v2

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v2

    mul-float/2addr v2, v1

    add-float/2addr v2, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    sub-float/2addr v2, v3

    .line 19
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    mul-float/2addr v3, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    mul-float/2addr v4, v1

    sub-float/2addr v3, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v3

    mul-float/2addr v3, v1

    add-float/2addr v3, v4

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    mul-float/2addr v4, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    mul-float/2addr v5, v1

    add-float/2addr v5, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v4

    mul-float/2addr v4, v1

    sub-float/2addr v5, v4

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v4

    mul-float/2addr v4, v1

    add-float/2addr v4, v5

    .line 21
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result v5

    mul-float/2addr v5, v1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v6

    mul-float/2addr v6, v1

    sub-float/2addr v5, v6

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v6

    mul-float/2addr v6, v1

    sub-float/2addr v5, v6

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result p1

    mul-float/2addr p1, p0

    sub-float/2addr v5, p1

    .line 22
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    return-object v0
.end method

.method public final toEulerAngles()Lcom/google/android/filament/utils/Float3;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x2

    .line 3
    invoke-static {p0, v0, v1, v0}, Lcom/google/android/filament/utils/QuaternionKt;->eulerAngles$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/RotationsOrder;ILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final toFloatArray()[F
    .locals 5

    .line 1
    iget v0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 2
    .line 3
    iget v1, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 4
    .line 5
    iget v2, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 6
    .line 7
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 8
    .line 9
    const/4 v3, 0x4

    .line 10
    new-array v3, v3, [F

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    aput v0, v3, v4

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    aput v1, v3, v0

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    aput v2, v3, v0

    .line 20
    .line 21
    const/4 v0, 0x3

    .line 22
    aput p0, v3, v0

    .line 23
    .line 24
    return-object v3
.end method

.method public final toMatrix()Lcom/google/android/filament/utils/Mat4;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/MatrixKt;->rotation(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 2
    .line 3
    iget v1, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 4
    .line 5
    iget v2, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 6
    .line 7
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "Quaternion(x="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", y="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", z="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", w="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method public final transform(Lay0/k;)Lcom/google/android/filament/utils/Quaternion;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")",
            "Lcom/google/android/filament/utils/Quaternion;"
        }
    .end annotation

    .line 1
    const-string v0, "block"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setX(F)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setY(F)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    check-cast v0, Ljava/lang/Number;

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Quaternion;->setZ(F)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    check-cast p1, Ljava/lang/Number;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Quaternion;->setW(F)V

    .line 88
    .line 89
    .line 90
    return-object p0
.end method

.method public final unaryMinus()Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 2
    .line 3
    iget v1, p0, Lcom/google/android/filament/utils/Quaternion;->x:F

    .line 4
    .line 5
    neg-float v1, v1

    .line 6
    iget v2, p0, Lcom/google/android/filament/utils/Quaternion;->y:F

    .line 7
    .line 8
    neg-float v2, v2

    .line 9
    iget v3, p0, Lcom/google/android/filament/utils/Quaternion;->z:F

    .line 10
    .line 11
    neg-float v3, v3

    .line 12
    iget p0, p0, Lcom/google/android/filament/utils/Quaternion;->w:F

    .line 13
    .line 14
    neg-float p0, p0

    .line 15
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
