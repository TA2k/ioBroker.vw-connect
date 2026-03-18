.class public final Lcom/google/android/filament/utils/Mat4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Mat4$Companion;,
        Lcom/google/android/filament/utils/Mat4$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0010\u0007\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0010\u000b\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0014\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008(\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0086\u0008\u0018\u0000 k2\u00020\u0001:\u0001kB/\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u0008B+\u0008\u0016\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0006\u0010\u000b\u001a\u00020\t\u0012\u0006\u0010\u000c\u001a\u00020\t\u0012\u0008\u0008\u0002\u0010\r\u001a\u00020\t\u00a2\u0006\u0004\u0008\u0007\u0010\u000eB\u0011\u0008\u0016\u0012\u0006\u0010\u000f\u001a\u00020\u0000\u00a2\u0006\u0004\u0008\u0007\u0010\u0010J\u0018\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u0011H\u0086\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J \u0010\u0013\u001a\u00020\u00162\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0015\u001a\u00020\u0011H\u0086\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u0017J\u0018\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u0018H\u0086\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u0019J \u0010\u0013\u001a\u00020\u00162\u0006\u0010\u0012\u001a\u00020\u00182\u0006\u0010\u0015\u001a\u00020\u0011H\u0086\u0002\u00a2\u0006\u0004\u0008\u0013\u0010\u001aJ \u0010\u001b\u001a\u00020\u00162\u0006\u0010\u0015\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0011H\u0086\u0002\u00a2\u0006\u0004\u0008\u001b\u0010\u0017J(\u0010\u001b\u001a\u00020\u001d2\u0006\u0010\u0015\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u001c\u001a\u00020\u0016H\u0086\u0002\u00a2\u0006\u0004\u0008\u001b\u0010\u001eJ \u0010\u001f\u001a\u00020\u001d2\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u001c\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008\u001f\u0010 J(\u0010\u001f\u001a\u00020\u001d2\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0015\u001a\u00020\u00112\u0006\u0010\u001c\u001a\u00020\u0016H\u0086\u0002\u00a2\u0006\u0004\u0008\u001f\u0010\u001eJ\u0010\u0010!\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008!\u0010\"J\u0010\u0010#\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008#\u0010\"J\u0010\u0010$\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008$\u0010\"J\u0018\u0010%\u001a\u00020\u00002\u0006\u0010\u001c\u001a\u00020\u0016H\u0086\u0002\u00a2\u0006\u0004\u0008%\u0010&J\u0018\u0010\'\u001a\u00020\u00002\u0006\u0010\u001c\u001a\u00020\u0016H\u0086\u0002\u00a2\u0006\u0004\u0008\'\u0010&J\u0018\u0010(\u001a\u00020\u00002\u0006\u0010\u001c\u001a\u00020\u0016H\u0086\u0002\u00a2\u0006\u0004\u0008(\u0010&J\u0018\u0010)\u001a\u00020\u00002\u0006\u0010\u001c\u001a\u00020\u0016H\u0086\u0002\u00a2\u0006\u0004\u0008)\u0010&J\"\u0010+\u001a\u00020\u00002\u0006\u0010\u001c\u001a\u00020\u00162\u0008\u0008\u0002\u0010*\u001a\u00020\u0016H\u0086\u0008\u00a2\u0006\u0004\u0008+\u0010,J\"\u0010.\u001a\u00020-2\u0006\u0010\u001c\u001a\u00020\u00162\u0008\u0008\u0002\u0010*\u001a\u00020\u0016H\u0086\u0008\u00a2\u0006\u0004\u0008.\u0010/J\u0018\u0010(\u001a\u00020\u00002\u0006\u0010\u000f\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008(\u00100J\"\u0010+\u001a\u00020\u00002\u0006\u0010\u000f\u001a\u00020\u00002\u0008\u0008\u0002\u0010*\u001a\u00020\u0016H\u0086\u0008\u00a2\u0006\u0004\u0008+\u00101J\"\u0010.\u001a\u00020-2\u0006\u0010\u000f\u001a\u00020\u00002\u0008\u0008\u0002\u0010*\u001a\u00020\u0016H\u0086\u0008\u00a2\u0006\u0004\u0008.\u00102J\u0018\u0010(\u001a\u00020\u00022\u0006\u0010\u001c\u001a\u00020\u0002H\u0086\u0002\u00a2\u0006\u0004\u0008(\u00103J\u0017\u00106\u001a\u00020\t2\u0008\u0008\u0002\u00105\u001a\u000204\u00a2\u0006\u0004\u00086\u00107J\r\u00109\u001a\u000208\u00a2\u0006\u0004\u00089\u0010:J\r\u0010<\u001a\u00020;\u00a2\u0006\u0004\u0008<\u0010=J\u000f\u0010?\u001a\u00020>H\u0016\u00a2\u0006\u0004\u0008?\u0010@J\u0010\u0010A\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008A\u0010BJ\u0010\u0010C\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008C\u0010BJ\u0010\u0010D\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008D\u0010BJ\u0010\u0010E\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008E\u0010BJ8\u0010F\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u0008F\u0010GJ\u0010\u0010H\u001a\u00020\u0011H\u00d6\u0001\u00a2\u0006\u0004\u0008H\u0010IJ\u001a\u0010.\u001a\u00020-2\u0008\u0010J\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u0008.\u0010KR\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010L\u001a\u0004\u0008M\u0010B\"\u0004\u0008N\u0010OR\"\u0010\u0004\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010L\u001a\u0004\u0008P\u0010B\"\u0004\u0008Q\u0010OR\"\u0010\u0005\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0005\u0010L\u001a\u0004\u0008R\u0010B\"\u0004\u0008S\u0010OR\"\u0010\u0006\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0006\u0010L\u001a\u0004\u0008T\u0010B\"\u0004\u0008U\u0010OR&\u0010\n\u001a\u00020\t2\u0006\u0010V\u001a\u00020\t8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008W\u0010X\"\u0004\u0008Y\u0010ZR&\u0010\u000b\u001a\u00020\t2\u0006\u0010V\u001a\u00020\t8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008[\u0010X\"\u0004\u0008\\\u0010ZR&\u0010\u000c\u001a\u00020\t2\u0006\u0010V\u001a\u00020\t8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008]\u0010X\"\u0004\u0008^\u0010ZR&\u0010\r\u001a\u00020\t2\u0006\u0010V\u001a\u00020\t8\u00c6\u0002@\u00c6\u0002X\u0086\u000e\u00a2\u0006\u000c\u001a\u0004\u0008_\u0010X\"\u0004\u0008`\u0010ZR\u0012\u0010b\u001a\u00020\t8\u00c6\u0002\u00a2\u0006\u0006\u001a\u0004\u0008a\u0010XR\u0012\u0010d\u001a\u00020\t8\u00c6\u0002\u00a2\u0006\u0006\u001a\u0004\u0008c\u0010XR\u0011\u0010f\u001a\u00020\t8F\u00a2\u0006\u0006\u001a\u0004\u0008e\u0010XR\u0012\u0010j\u001a\u00020g8\u00c6\u0002\u00a2\u0006\u0006\u001a\u0004\u0008h\u0010i\u00a8\u0006l"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Mat4;",
        "",
        "Lcom/google/android/filament/utils/Float4;",
        "x",
        "y",
        "z",
        "w",
        "<init>",
        "(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V",
        "Lcom/google/android/filament/utils/Float3;",
        "right",
        "up",
        "forward",
        "position",
        "(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V",
        "m",
        "(Lcom/google/android/filament/utils/Mat4;)V",
        "",
        "column",
        "get",
        "(I)Lcom/google/android/filament/utils/Float4;",
        "row",
        "",
        "(II)F",
        "Lcom/google/android/filament/utils/MatrixColumn;",
        "(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float4;",
        "(Lcom/google/android/filament/utils/MatrixColumn;I)F",
        "invoke",
        "v",
        "Llx0/b0;",
        "(IIF)V",
        "set",
        "(ILcom/google/android/filament/utils/Float4;)V",
        "unaryMinus",
        "()Lcom/google/android/filament/utils/Mat4;",
        "inc",
        "dec",
        "plus",
        "(F)Lcom/google/android/filament/utils/Mat4;",
        "minus",
        "times",
        "div",
        "delta",
        "compareTo",
        "(FF)Lcom/google/android/filament/utils/Mat4;",
        "",
        "equals",
        "(FF)Z",
        "(Lcom/google/android/filament/utils/Mat4;)Lcom/google/android/filament/utils/Mat4;",
        "(Lcom/google/android/filament/utils/Mat4;F)Lcom/google/android/filament/utils/Mat4;",
        "(Lcom/google/android/filament/utils/Mat4;F)Z",
        "(Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Float4;",
        "Lcom/google/android/filament/utils/RotationsOrder;",
        "order",
        "toEulerAngles",
        "(Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;",
        "Lcom/google/android/filament/utils/Quaternion;",
        "toQuaternion",
        "()Lcom/google/android/filament/utils/Quaternion;",
        "",
        "toFloatArray",
        "()[F",
        "",
        "toString",
        "()Ljava/lang/String;",
        "component1",
        "()Lcom/google/android/filament/utils/Float4;",
        "component2",
        "component3",
        "component4",
        "copy",
        "(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Mat4;",
        "hashCode",
        "()I",
        "other",
        "(Ljava/lang/Object;)Z",
        "Lcom/google/android/filament/utils/Float4;",
        "getX",
        "setX",
        "(Lcom/google/android/filament/utils/Float4;)V",
        "getY",
        "setY",
        "getZ",
        "setZ",
        "getW",
        "setW",
        "value",
        "getRight",
        "()Lcom/google/android/filament/utils/Float3;",
        "setRight",
        "(Lcom/google/android/filament/utils/Float3;)V",
        "getUp",
        "setUp",
        "getForward",
        "setForward",
        "getPosition",
        "setPosition",
        "getScale",
        "scale",
        "getTranslation",
        "translation",
        "getRotation",
        "rotation",
        "Lcom/google/android/filament/utils/Mat3;",
        "getUpperLeft",
        "()Lcom/google/android/filament/utils/Mat3;",
        "upperLeft",
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
.field public static final Companion:Lcom/google/android/filament/utils/Mat4$Companion;


# instance fields
.field private w:Lcom/google/android/filament/utils/Float4;

.field private x:Lcom/google/android/filament/utils/Float4;

.field private y:Lcom/google/android/filament/utils/Float4;

.field private z:Lcom/google/android/filament/utils/Float4;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/Mat4$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/filament/utils/Mat4;->Companion:Lcom/google/android/filament/utils/Mat4$Companion;

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

    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V
    .locals 4

    const-string v0, "right"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "up"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "forward"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "position"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    const/4 v1, 0x0

    const/4 v2, 0x2

    const/4 v3, 0x0

    invoke-direct {v0, p1, v1, v2, v3}, Lcom/google/android/filament/utils/Float4;-><init>(Lcom/google/android/filament/utils/Float3;FILkotlin/jvm/internal/g;)V

    new-instance p1, Lcom/google/android/filament/utils/Float4;

    invoke-direct {p1, p2, v1, v2, v3}, Lcom/google/android/filament/utils/Float4;-><init>(Lcom/google/android/filament/utils/Float3;FILkotlin/jvm/internal/g;)V

    new-instance p2, Lcom/google/android/filament/utils/Float4;

    invoke-direct {p2, p3, v1, v2, v3}, Lcom/google/android/filament/utils/Float4;-><init>(Lcom/google/android/filament/utils/Float3;FILkotlin/jvm/internal/g;)V

    new-instance p3, Lcom/google/android/filament/utils/Float4;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-direct {p3, p4, v1}, Lcom/google/android/filament/utils/Float4;-><init>(Lcom/google/android/filament/utils/Float3;F)V

    invoke-direct {p0, v0, p1, p2, p3}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-void
.end method

.method public synthetic constructor <init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;ILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    .line 12
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    const/4 v4, 0x7

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/utils/Float3;-><init>(FFFILkotlin/jvm/internal/g;)V

    move-object p4, v0

    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V
    .locals 1

    const-string v0, "x"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "y"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "z"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "w"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    iput-object p2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 5
    iput-object p3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 6
    iput-object p4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    return-void
.end method

.method public synthetic constructor <init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;ILkotlin/jvm/internal/g;)V
    .locals 7

    and-int/lit8 p6, p5, 0x1

    if-eqz p6, :cond_0

    .line 7
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    const/16 v5, 0xe

    const/4 v6, 0x0

    const/high16 v1, 0x3f800000    # 1.0f

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Float4;-><init>(FFFFILkotlin/jvm/internal/g;)V

    move-object p1, v0

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    .line 8
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    const/16 v5, 0xd

    const/4 v6, 0x0

    const/4 v1, 0x0

    const/high16 v2, 0x3f800000    # 1.0f

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Float4;-><init>(FFFFILkotlin/jvm/internal/g;)V

    move-object p2, v0

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    .line 9
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    const/16 v5, 0xb

    const/4 v6, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/high16 v3, 0x3f800000    # 1.0f

    const/4 v4, 0x0

    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Float4;-><init>(FFFFILkotlin/jvm/internal/g;)V

    move-object p3, v0

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    .line 10
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    const/4 v5, 0x7

    const/4 v6, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-direct/range {v0 .. v6}, Lcom/google/android/filament/utils/Float4;-><init>(FFFFILkotlin/jvm/internal/g;)V

    move-object p4, v0

    .line 11
    :cond_3
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/utils/Mat4;)V
    .locals 10

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    iget-object v1, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    const/16 v6, 0xf

    const/4 v7, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v1 .. v7}, Lcom/google/android/filament/utils/Float4;->copy$default(Lcom/google/android/filament/utils/Float4;FFFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    iget-object v1, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-static/range {v1 .. v7}, Lcom/google/android/filament/utils/Float4;->copy$default(Lcom/google/android/filament/utils/Float4;FFFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    iget-object v2, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    const/16 v7, 0xf

    const/4 v8, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v8}, Lcom/google/android/filament/utils/Float4;->copy$default(Lcom/google/android/filament/utils/Float4;FFFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float4;

    move-result-object v2

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    const/16 v8, 0xf

    const/4 v9, 0x0

    const/4 v7, 0x0

    invoke-static/range {v3 .. v9}, Lcom/google/android/filament/utils/Float4;->copy$default(Lcom/google/android/filament/utils/Float4;FFFFILjava/lang/Object;)Lcom/google/android/filament/utils/Float4;

    move-result-object p1

    invoke-direct {p0, v0, v1, v2, p1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-void
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Mat4;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Mat4;
    .locals 8

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 1
    :cond_0
    new-instance p3, Lcom/google/android/filament/utils/Mat4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    .line 3
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

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
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

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
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v4

    sub-float v5, v4, p1

    .line 11
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_3

    move v4, p4

    goto :goto_2

    .line 12
    :cond_3
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 13
    :goto_2
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    sub-float v5, v0, p1

    .line 14
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_4

    move v0, p4

    goto :goto_3

    .line 15
    :cond_4
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 16
    :goto_3
    invoke-direct {v1, v2, v3, v4, v0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 17
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    .line 18
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 19
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    sub-float v4, v3, p1

    .line 20
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_5

    move v3, p4

    goto :goto_4

    .line 21
    :cond_5
    invoke-static {v3, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 22
    :goto_4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    sub-float v5, v4, p1

    .line 23
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_6

    move v4, p4

    goto :goto_5

    .line 24
    :cond_6
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 25
    :goto_5
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    sub-float v6, v5, p1

    .line 26
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_7

    move v5, p4

    goto :goto_6

    .line 27
    :cond_7
    invoke-static {v5, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 28
    :goto_6
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    sub-float v6, v0, p1

    .line 29
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_8

    move v0, p4

    goto :goto_7

    .line 30
    :cond_8
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 31
    :goto_7
    invoke-direct {v2, v3, v4, v5, v0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 32
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    .line 33
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 34
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    sub-float v5, v4, p1

    .line 35
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_9

    move v4, p4

    goto :goto_8

    .line 36
    :cond_9
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 37
    :goto_8
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    sub-float v6, v5, p1

    .line 38
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_a

    move v5, p4

    goto :goto_9

    .line 39
    :cond_a
    invoke-static {v5, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 40
    :goto_9
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    sub-float v7, v6, p1

    .line 41
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_b

    move v6, p4

    goto :goto_a

    .line 42
    :cond_b
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 43
    :goto_a
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    sub-float v7, v0, p1

    .line 44
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_c

    move v0, p4

    goto :goto_b

    .line 45
    :cond_c
    invoke-static {v0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 46
    :goto_b
    invoke-direct {v3, v4, v5, v6, v0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 47
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    .line 48
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 49
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    sub-float v5, v4, p1

    .line 50
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_d

    move v4, p4

    goto :goto_c

    .line 51
    :cond_d
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 52
    :goto_c
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    sub-float v6, v5, p1

    .line 53
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_e

    move v5, p4

    goto :goto_d

    .line 54
    :cond_e
    invoke-static {v5, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 55
    :goto_d
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    sub-float v7, v6, p1

    .line 56
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_f

    move v6, p4

    goto :goto_e

    .line 57
    :cond_f
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 58
    :goto_e
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    sub-float v7, p0, p1

    .line 59
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float p2, v7, p2

    if-gez p2, :cond_10

    goto :goto_f

    .line 60
    :cond_10
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 61
    :goto_f
    invoke-direct {v0, v4, v5, v6, p4}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 62
    invoke-direct {p3, v1, v2, v3, v0}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-object p3
.end method

.method public static synthetic compareTo$default(Lcom/google/android/filament/utils/Mat4;Lcom/google/android/filament/utils/Mat4;FILjava/lang/Object;)Lcom/google/android/filament/utils/Mat4;
    .locals 10

    and-int/lit8 p3, p3, 0x2

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    move p2, p4

    .line 63
    :cond_0
    const-string p3, "m"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Mat4;

    .line 64
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 65
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 66
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    sub-float v5, v3, v4

    .line 67
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_1

    move v3, p4

    goto :goto_0

    .line 68
    :cond_1
    invoke-static {v3, v4}, Ljava/lang/Float;->compare(FF)I

    move-result v3

    int-to-float v3, v3

    .line 69
    :goto_0
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    sub-float v6, v4, v5

    .line 70
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_2

    move v4, p4

    goto :goto_1

    .line 71
    :cond_2
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 72
    :goto_1
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    sub-float v7, v5, v6

    .line 73
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_3

    move v5, p4

    goto :goto_2

    .line 74
    :cond_3
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 75
    :goto_2
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    sub-float v6, v0, v1

    .line 76
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_4

    move v0, p4

    goto :goto_3

    .line 77
    :cond_4
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 78
    :goto_3
    invoke-direct {v2, v3, v4, v5, v0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 79
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 80
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 81
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    sub-float v6, v4, v5

    .line 82
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_5

    move v4, p4

    goto :goto_4

    .line 83
    :cond_5
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 84
    :goto_4
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    sub-float v7, v5, v6

    .line 85
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_6

    move v5, p4

    goto :goto_5

    .line 86
    :cond_6
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 87
    :goto_5
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    sub-float v8, v6, v7

    .line 88
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_7

    move v6, p4

    goto :goto_6

    .line 89
    :cond_7
    invoke-static {v6, v7}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 90
    :goto_6
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    sub-float v7, v0, v1

    .line 91
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_8

    move v0, p4

    goto :goto_7

    .line 92
    :cond_8
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 93
    :goto_7
    invoke-direct {v3, v4, v5, v6, v0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 94
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 95
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 96
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    sub-float v7, v5, v6

    .line 97
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_9

    move v5, p4

    goto :goto_8

    .line 98
    :cond_9
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 99
    :goto_8
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v7

    sub-float v8, v6, v7

    .line 100
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_a

    move v6, p4

    goto :goto_9

    .line 101
    :cond_a
    invoke-static {v6, v7}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 102
    :goto_9
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    sub-float v9, v7, v8

    .line 103
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_b

    move v7, p4

    goto :goto_a

    .line 104
    :cond_b
    invoke-static {v7, v8}, Ljava/lang/Float;->compare(FF)I

    move-result v7

    int-to-float v7, v7

    .line 105
    :goto_a
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    sub-float v8, v0, v1

    .line 106
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_c

    move v0, p4

    goto :goto_b

    .line 107
    :cond_c
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    int-to-float v0, v0

    .line 108
    :goto_b
    invoke-direct {v4, v5, v6, v7, v0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 109
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p1

    .line 110
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 111
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    sub-float v6, v1, v5

    .line 112
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_d

    move v1, p4

    goto :goto_c

    .line 113
    :cond_d
    invoke-static {v1, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 114
    :goto_c
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    sub-float v7, v5, v6

    .line 115
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_e

    move v5, p4

    goto :goto_d

    .line 116
    :cond_e
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 117
    :goto_d
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    sub-float v8, v6, v7

    .line 118
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_f

    move v6, p4

    goto :goto_e

    .line 119
    :cond_f
    invoke-static {v6, v7}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 120
    :goto_e
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    sub-float v7, p0, p1

    .line 121
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float p2, v7, p2

    if-gez p2, :cond_10

    goto :goto_f

    .line 122
    :cond_10
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float p4, p0

    .line 123
    :goto_f
    invoke-direct {v0, v1, v5, v6, p4}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 124
    invoke-direct {p3, v2, v3, v4, v0}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-object p3
.end method

.method public static synthetic copy$default(Lcom/google/android/filament/utils/Mat4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;ILjava/lang/Object;)Lcom/google/android/filament/utils/Mat4;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Mat4;->copy(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Mat4;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Mat4;FFILjava/lang/Object;)Z
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object p3

    .line 2
    invoke-static {p3, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 3
    invoke-static {p3, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 4
    invoke-static {p3, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 5
    invoke-static {p3, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object p3

    .line 7
    invoke-static {p3, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 8
    invoke-static {p3, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 9
    invoke-static {p3, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 10
    invoke-static {p3, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object p3

    .line 12
    invoke-static {p3, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 13
    invoke-static {p3, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 14
    invoke-static {p3, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result p4

    cmpg-float p4, p4, p2

    if-gez p4, :cond_1

    .line 15
    invoke-static {p3, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    .line 17
    invoke-static {p0, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 18
    invoke-static {p0, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 19
    invoke-static {p0, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 20
    invoke-static {p0, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static synthetic equals$default(Lcom/google/android/filament/utils/Mat4;Lcom/google/android/filament/utils/Mat4;FILjava/lang/Object;)Z
    .locals 1

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 29
    :cond_0
    const-string p3, "m"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object p4

    .line 31
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v0

    .line 32
    invoke-static {p4, v0}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 33
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v0

    .line 34
    invoke-static {p4, v0}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 35
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v0

    .line 36
    invoke-static {p4, v0}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 37
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p3

    .line 38
    invoke-static {p4, p3}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object p4

    .line 40
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v0

    .line 41
    invoke-static {p4, v0}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 42
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v0

    .line 43
    invoke-static {p4, v0}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 44
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v0

    .line 45
    invoke-static {p4, v0}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 46
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p3

    .line 47
    invoke-static {p4, p3}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 48
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object p3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object p4

    .line 49
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v0

    .line 50
    invoke-static {p4, v0}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 51
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v0

    .line 52
    invoke-static {p4, v0}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 53
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v0

    .line 54
    invoke-static {p4, v0}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_1

    .line 55
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p3

    .line 56
    invoke-static {p4, p3}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 57
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p1

    .line 58
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result p3

    .line 59
    invoke-static {p1, p3}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 60
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result p3

    .line 61
    invoke-static {p1, p3}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 62
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result p3

    .line 63
    invoke-static {p1, p3}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result p3

    cmpg-float p3, p3, p2

    if-gez p3, :cond_1

    .line 64
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    .line 65
    invoke-static {p1, p0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static synthetic toEulerAngles$default(Lcom/google/android/filament/utils/Mat4;Lcom/google/android/filament/utils/RotationsOrder;ILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    sget-object p1, Lcom/google/android/filament/utils/RotationsOrder;->ZYX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat4;->toEulerAngles(Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final compareTo(FF)Lcom/google/android/filament/utils/Mat4;
    .locals 10

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 3
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

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
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

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
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    sub-float v7, v6, p1

    .line 11
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_2

    move v6, v5

    goto :goto_2

    .line 12
    :cond_2
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 13
    :goto_2
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    sub-float v7, v1, p1

    .line 14
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_3

    move v1, v5

    goto :goto_3

    .line 15
    :cond_3
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 16
    :goto_3
    invoke-direct {v2, v3, v4, v6, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 17
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 18
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 19
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    sub-float v6, v4, p1

    .line 20
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    if-gez v6, :cond_4

    move v4, v5

    goto :goto_4

    .line 21
    :cond_4
    invoke-static {v4, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 22
    :goto_4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    sub-float v7, v6, p1

    .line 23
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_5

    move v6, v5

    goto :goto_5

    .line 24
    :cond_5
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 25
    :goto_5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    sub-float v8, v7, p1

    .line 26
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_6

    move v7, v5

    goto :goto_6

    .line 27
    :cond_6
    invoke-static {v7, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v7

    int-to-float v7, v7

    .line 28
    :goto_6
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    sub-float v8, v1, p1

    .line 29
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_7

    move v1, v5

    goto :goto_7

    .line 30
    :cond_7
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 31
    :goto_7
    invoke-direct {v3, v4, v6, v7, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 32
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 33
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    sub-float v7, v6, p1

    .line 35
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_8

    move v6, v5

    goto :goto_8

    .line 36
    :cond_8
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 37
    :goto_8
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v7

    sub-float v8, v7, p1

    .line 38
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_9

    move v7, v5

    goto :goto_9

    .line 39
    :cond_9
    invoke-static {v7, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v7

    int-to-float v7, v7

    .line 40
    :goto_9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    sub-float v9, v8, p1

    .line 41
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_a

    move v8, v5

    goto :goto_a

    .line 42
    :cond_a
    invoke-static {v8, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    int-to-float v8, v8

    .line 43
    :goto_a
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    sub-float v9, v1, p1

    .line 44
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_b

    move v1, v5

    goto :goto_b

    .line 45
    :cond_b
    invoke-static {v1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 46
    :goto_b
    invoke-direct {v4, v6, v7, v8, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 47
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    .line 48
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 49
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    sub-float v7, v6, p1

    .line 50
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    move-result v7

    cmpg-float v7, v7, p2

    if-gez v7, :cond_c

    move v6, v5

    goto :goto_c

    .line 51
    :cond_c
    invoke-static {v6, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 52
    :goto_c
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v7

    sub-float v8, v7, p1

    .line 53
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_d

    move v7, v5

    goto :goto_d

    .line 54
    :cond_d
    invoke-static {v7, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v7

    int-to-float v7, v7

    .line 55
    :goto_d
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    sub-float v9, v8, p1

    .line 56
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_e

    move v8, v5

    goto :goto_e

    .line 57
    :cond_e
    invoke-static {v8, p1}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    int-to-float v8, v8

    .line 58
    :goto_e
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    sub-float v9, p0, p1

    .line 59
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float p2, v9, p2

    if-gez p2, :cond_f

    goto :goto_f

    .line 60
    :cond_f
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v5, p0

    .line 61
    :goto_f
    invoke-direct {v1, v6, v7, v8, v5}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 62
    invoke-direct {v0, v2, v3, v4, v1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-object v0
.end method

.method public final compareTo(Lcom/google/android/filament/utils/Mat4;F)Lcom/google/android/filament/utils/Mat4;
    .locals 12

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 64
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v2

    .line 65
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 66
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    sub-float v6, v4, v5

    .line 67
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    move-result v6

    cmpg-float v6, v6, p2

    const/4 v7, 0x0

    if-gez v6, :cond_0

    move v4, v7

    goto :goto_0

    .line 68
    :cond_0
    invoke-static {v4, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v4

    int-to-float v4, v4

    .line 69
    :goto_0
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    sub-float v8, v5, v6

    .line 70
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_1

    move v5, v7

    goto :goto_1

    .line 71
    :cond_1
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 72
    :goto_1
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    sub-float v9, v6, v8

    .line 73
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_2

    move v6, v7

    goto :goto_2

    .line 74
    :cond_2
    invoke-static {v6, v8}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 75
    :goto_2
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v2

    sub-float v8, v1, v2

    .line 76
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_3

    move v1, v7

    goto :goto_3

    .line 77
    :cond_3
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 78
    :goto_3
    invoke-direct {v3, v4, v5, v6, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 79
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v2

    .line 80
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 81
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    sub-float v8, v5, v6

    .line 82
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_4

    move v5, v7

    goto :goto_4

    .line 83
    :cond_4
    invoke-static {v5, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    int-to-float v5, v5

    .line 84
    :goto_4
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v8

    sub-float v9, v6, v8

    .line 85
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_5

    move v6, v7

    goto :goto_5

    .line 86
    :cond_5
    invoke-static {v6, v8}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 87
    :goto_5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v9

    sub-float v10, v8, v9

    .line 88
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    move-result v10

    cmpg-float v10, v10, p2

    if-gez v10, :cond_6

    move v8, v7

    goto :goto_6

    .line 89
    :cond_6
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    int-to-float v8, v8

    .line 90
    :goto_6
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v2

    sub-float v9, v1, v2

    .line 91
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_7

    move v1, v7

    goto :goto_7

    .line 92
    :cond_7
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 93
    :goto_7
    invoke-direct {v4, v5, v6, v8, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 94
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v2

    .line 95
    new-instance v5, Lcom/google/android/filament/utils/Float4;

    .line 96
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v8

    sub-float v9, v6, v8

    .line 97
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_8

    move v6, v7

    goto :goto_8

    .line 98
    :cond_8
    invoke-static {v6, v8}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 99
    :goto_8
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v8

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v9

    sub-float v10, v8, v9

    .line 100
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    move-result v10

    cmpg-float v10, v10, p2

    if-gez v10, :cond_9

    move v8, v7

    goto :goto_9

    .line 101
    :cond_9
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    int-to-float v8, v8

    .line 102
    :goto_9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v9

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v10

    sub-float v11, v9, v10

    .line 103
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    move-result v11

    cmpg-float v11, v11, p2

    if-gez v11, :cond_a

    move v9, v7

    goto :goto_a

    .line 104
    :cond_a
    invoke-static {v9, v10}, Ljava/lang/Float;->compare(FF)I

    move-result v9

    int-to-float v9, v9

    .line 105
    :goto_a
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v2

    sub-float v10, v1, v2

    .line 106
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    move-result v10

    cmpg-float v10, v10, p2

    if-gez v10, :cond_b

    move v1, v7

    goto :goto_b

    .line 107
    :cond_b
    invoke-static {v1, v2}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    int-to-float v1, v1

    .line 108
    :goto_b
    invoke-direct {v5, v6, v8, v9, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 109
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p1

    .line 110
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 111
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    sub-float v8, v2, v6

    .line 112
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    move-result v8

    cmpg-float v8, v8, p2

    if-gez v8, :cond_c

    move v2, v7

    goto :goto_c

    .line 113
    :cond_c
    invoke-static {v2, v6}, Ljava/lang/Float;->compare(FF)I

    move-result v2

    int-to-float v2, v2

    .line 114
    :goto_c
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v8

    sub-float v9, v6, v8

    .line 115
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float v9, v9, p2

    if-gez v9, :cond_d

    move v6, v7

    goto :goto_d

    .line 116
    :cond_d
    invoke-static {v6, v8}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    int-to-float v6, v6

    .line 117
    :goto_d
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v9

    sub-float v10, v8, v9

    .line 118
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    move-result v10

    cmpg-float v10, v10, p2

    if-gez v10, :cond_e

    move v8, v7

    goto :goto_e

    .line 119
    :cond_e
    invoke-static {v8, v9}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    int-to-float v8, v8

    .line 120
    :goto_e
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    sub-float v9, p0, p1

    .line 121
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v9

    cmpg-float p2, v9, p2

    if-gez p2, :cond_f

    goto :goto_f

    .line 122
    :cond_f
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p0

    int-to-float v7, p0

    .line 123
    :goto_f
    invoke-direct {v1, v2, v6, v8, v7}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 124
    invoke-direct {v0, v3, v4, v5, v1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-object v0
.end method

.method public final component1()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Mat4;
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
    const-string p0, "w"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Lcom/google/android/filament/utils/Mat4;

    .line 22
    .line 23
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method

.method public final dec()Lcom/google/android/filament/utils/Mat4;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->dec()Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iput-object v2, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->dec()Lcom/google/android/filament/utils/Float4;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 18
    .line 19
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->dec()Lcom/google/android/filament/utils/Float4;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    iput-object v4, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 26
    .line 27
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 28
    .line 29
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->dec()Lcom/google/android/filament/utils/Float4;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    iput-object v5, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 34
    .line 35
    invoke-direct {v0, v1, v2, v3, v4}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 36
    .line 37
    .line 38
    return-object v0
.end method

.method public final div(F)Lcom/google/android/filament/utils/Mat4;
    .locals 8

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    div-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    div-float/2addr v4, p1

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    div-float/2addr v5, p1

    .line 22
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    div-float/2addr v1, p1

    .line 27
    invoke-direct {v2, v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 31
    .line 32
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 33
    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    div-float/2addr v4, p1

    .line 39
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    div-float/2addr v5, p1

    .line 44
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    div-float/2addr v6, p1

    .line 49
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    div-float/2addr v1, p1

    .line 54
    invoke-direct {v3, v4, v5, v6, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 58
    .line 59
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 60
    .line 61
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    div-float/2addr v5, p1

    .line 66
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    div-float/2addr v6, p1

    .line 71
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    div-float/2addr v7, p1

    .line 76
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    div-float/2addr v1, p1

    .line 81
    invoke-direct {v4, v5, v6, v7, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 85
    .line 86
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 87
    .line 88
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    div-float/2addr v5, p1

    .line 93
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    div-float/2addr v6, p1

    .line 98
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    div-float/2addr v7, p1

    .line 103
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    div-float/2addr p0, p1

    .line 108
    invoke-direct {v1, v5, v6, v7, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 109
    .line 110
    .line 111
    invoke-direct {v0, v2, v3, v4, v1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 112
    .line 113
    .line 114
    return-object v0
.end method

.method public final equals(FF)Z
    .locals 2

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    .line 3
    invoke-static {v0, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 4
    invoke-static {v0, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 5
    invoke-static {v0, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 6
    invoke-static {v0, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    .line 8
    invoke-static {v0, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 9
    invoke-static {v0, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 10
    invoke-static {v0, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 11
    invoke-static {v0, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    .line 13
    invoke-static {v0, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 14
    invoke-static {v0, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 15
    invoke-static {v0, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result v1

    cmpg-float v1, v1, p2

    if-gez v1, :cond_0

    .line 16
    invoke-static {v0, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 17
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    .line 18
    invoke-static {p0, p1}, Lc1/j0;->A(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 19
    invoke-static {p0, p1}, Lc1/j0;->B(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 20
    invoke-static {p0, p1}, Lc1/j0;->C(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 21
    invoke-static {p0, p1}, Lc1/j0;->y(Lcom/google/android/filament/utils/Float4;F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final equals(Lcom/google/android/filament/utils/Mat4;F)Z
    .locals 3

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 31
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    .line 32
    invoke-static {v1, v2}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 33
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v2

    .line 34
    invoke-static {v1, v2}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 35
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v2

    .line 36
    invoke-static {v1, v2}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 37
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    .line 38
    invoke-static {v1, v0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 40
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    .line 41
    invoke-static {v1, v2}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 42
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v2

    .line 43
    invoke-static {v1, v2}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 44
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v2

    .line 45
    invoke-static {v1, v2}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 46
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    .line 47
    invoke-static {v1, v0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 48
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    move-result-object v1

    .line 49
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    .line 50
    invoke-static {v1, v2}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 51
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v2

    .line 52
    invoke-static {v1, v2}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 53
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v2

    .line 54
    invoke-static {v1, v2}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_0

    .line 55
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v0

    .line 56
    invoke-static {v1, v0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 57
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    move-result-object p1

    .line 58
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v0

    .line 59
    invoke-static {p1, v0}, Lc1/j0;->o(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 60
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v0

    .line 61
    invoke-static {p1, v0}, Lc1/j0;->s(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 62
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v0

    .line 63
    invoke-static {p1, v0}, Lc1/j0;->w(Lcom/google/android/filament/utils/Float4;F)F

    move-result v0

    cmpg-float v0, v0, p2

    if-gez v0, :cond_0

    .line 64
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    .line 65
    invoke-static {p1, p0}, Lc1/j0;->e(Lcom/google/android/filament/utils/Float4;F)F

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
    instance-of v1, p1, Lcom/google/android/filament/utils/Mat4;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Lcom/google/android/filament/utils/Mat4;

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    return v2

    :cond_2
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    return v2

    :cond_3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    return v2

    :cond_4
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_5

    return v2

    :cond_5
    return v0
.end method

.method public final get(II)F
    .locals 0

    .line 6
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat4;->get(I)Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Float4;->get(I)F

    move-result p0

    return p0
.end method

.method public final get(Lcom/google/android/filament/utils/MatrixColumn;I)F
    .locals 1

    const-string v0, "column"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat4;->get(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Float4;->get(I)F

    move-result p0

    return p0
.end method

.method public final get(I)Lcom/google/android/filament/utils/Float4;
    .locals 1

    if-eqz p1, :cond_3

    const/4 v0, 0x1

    if-eq p1, v0, :cond_2

    const/4 v0, 0x2

    if-eq p1, v0, :cond_1

    const/4 v0, 0x3

    if-ne p1, v0, :cond_0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    return-object p0

    .line 2
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "column must be in 0..3"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 3
    :cond_1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    return-object p0

    .line 4
    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    return-object p0

    .line 5
    :cond_3
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    return-object p0
.end method

.method public final get(Lcom/google/android/filament/utils/MatrixColumn;)Lcom/google/android/filament/utils/Float4;
    .locals 1

    const-string v0, "column"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    sget-object v0, Lcom/google/android/filament/utils/Mat4$WhenMappings;->$EnumSwitchMapping$0:[I

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

    .line 8
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    return-object p0

    .line 9
    :cond_0
    new-instance p0, La8/r0;

    .line 10
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 11
    throw p0

    .line 12
    :cond_1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    return-object p0

    .line 13
    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    return-object p0

    .line 14
    :cond_3
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    return-object p0
.end method

.method public final getForward()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final getPosition()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final getRight()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final getRotation()Lcom/google/android/filament/utils/Float3;
    .locals 9

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-direct {v1, v2, v3, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 20
    .line 21
    .line 22
    invoke-static {v1}, Lcom/google/android/filament/utils/VectorKt;->normalize(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 31
    .line 32
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 45
    .line 46
    .line 47
    invoke-static {v2}, Lcom/google/android/filament/utils/VectorKt;->normalize(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 56
    .line 57
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    invoke-direct {v2, v3, v4, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 70
    .line 71
    .line 72
    invoke-static {v2}, Lcom/google/android/filament/utils/VectorKt;->normalize(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Float3;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    const/high16 v3, -0x40800000    # -1.0f

    .line 81
    .line 82
    cmpg-float v2, v2, v3

    .line 83
    .line 84
    const/4 v3, 0x0

    .line 85
    const v4, 0x42652ee0

    .line 86
    .line 87
    .line 88
    if-gtz v2, :cond_0

    .line 89
    .line 90
    new-instance p0, Lcom/google/android/filament/utils/Float3;

    .line 91
    .line 92
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    float-to-double v5, v0

    .line 97
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    float-to-double v0, v0

    .line 102
    invoke-static {v5, v6, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    .line 103
    .line 104
    .line 105
    move-result-wide v0

    .line 106
    double-to-float v0, v0

    .line 107
    mul-float/2addr v0, v4

    .line 108
    const/high16 v1, -0x3d4c0000    # -90.0f

    .line 109
    .line 110
    invoke-direct {p0, v1, v3, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 111
    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    const/high16 v5, 0x3f800000    # 1.0f

    .line 119
    .line 120
    cmpl-float v2, v2, v5

    .line 121
    .line 122
    if-ltz v2, :cond_1

    .line 123
    .line 124
    new-instance p0, Lcom/google/android/filament/utils/Float3;

    .line 125
    .line 126
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    neg-float v0, v0

    .line 131
    float-to-double v5, v0

    .line 132
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    neg-float v0, v0

    .line 137
    float-to-double v0, v0

    .line 138
    invoke-static {v5, v6, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    .line 139
    .line 140
    .line 141
    move-result-wide v0

    .line 142
    double-to-float v0, v0

    .line 143
    mul-float/2addr v0, v4

    .line 144
    const/high16 v1, 0x42b40000    # 90.0f

    .line 145
    .line 146
    invoke-direct {p0, v1, v3, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 147
    .line 148
    .line 149
    return-object p0

    .line 150
    :cond_1
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 151
    .line 152
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    float-to-double v5, v3

    .line 157
    invoke-static {v5, v6}, Ljava/lang/Math;->asin(D)D

    .line 158
    .line 159
    .line 160
    move-result-wide v5

    .line 161
    double-to-float v3, v5

    .line 162
    neg-float v3, v3

    .line 163
    mul-float/2addr v3, v4

    .line 164
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 165
    .line 166
    .line 167
    move-result v5

    .line 168
    float-to-double v5, v5

    .line 169
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 170
    .line 171
    .line 172
    move-result p0

    .line 173
    float-to-double v7, p0

    .line 174
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->atan2(DD)D

    .line 175
    .line 176
    .line 177
    move-result-wide v5

    .line 178
    double-to-float p0, v5

    .line 179
    neg-float p0, p0

    .line 180
    mul-float/2addr p0, v4

    .line 181
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    float-to-double v5, v0

    .line 186
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    float-to-double v0, v0

    .line 191
    invoke-static {v5, v6, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    .line 192
    .line 193
    .line 194
    move-result-wide v0

    .line 195
    double-to-float v0, v0

    .line 196
    mul-float/2addr v0, v4

    .line 197
    invoke-direct {v2, v3, p0, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 198
    .line 199
    .line 200
    return-object v2
.end method

.method public final getScale()Lcom/google/android/filament/utils/Float3;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    mul-float/2addr v3, v1

    .line 33
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    invoke-static {v2, v1, v3}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    invoke-static {v2, v3, v1}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    float-to-double v1, v1

    .line 50
    invoke-static {v1, v2}, Ljava/lang/Math;->sqrt(D)D

    .line 51
    .line 52
    .line 53
    move-result-wide v1

    .line 54
    double-to-float v1, v1

    .line 55
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 60
    .line 61
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    invoke-direct {v3, v4, v5, v2}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    mul-float/2addr v4, v2

    .line 85
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    invoke-static {v3, v2, v4}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    invoke-static {v3, v4, v2}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    float-to-double v2, v2

    .line 102
    invoke-static {v2, v3}, Ljava/lang/Math;->sqrt(D)D

    .line 103
    .line 104
    .line 105
    move-result-wide v2

    .line 106
    double-to-float v2, v2

    .line 107
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 112
    .line 113
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    invoke-direct {v3, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 133
    .line 134
    .line 135
    move-result v4

    .line 136
    mul-float/2addr v4, p0

    .line 137
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    invoke-static {v3, p0, v4}, Lc1/j0;->d(Lcom/google/android/filament/utils/Float3;FF)F

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 146
    .line 147
    .line 148
    move-result v4

    .line 149
    invoke-static {v3, v4, p0}, Lc1/j0;->n(Lcom/google/android/filament/utils/Float3;FF)F

    .line 150
    .line 151
    .line 152
    move-result p0

    .line 153
    float-to-double v3, p0

    .line 154
    invoke-static {v3, v4}, Ljava/lang/Math;->sqrt(D)D

    .line 155
    .line 156
    .line 157
    move-result-wide v3

    .line 158
    double-to-float p0, v3

    .line 159
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 160
    .line 161
    .line 162
    return-object v0
.end method

.method public final getTranslation()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final getUp()Lcom/google/android/filament/utils/Float3;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-direct {v0, v1, v2, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public final getUpperLeft()Lcom/google/android/filament/utils/Mat3;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat3;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 8
    .line 9
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-direct {v2, v3, v4, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    new-instance v3, Lcom/google/android/filament/utils/Float3;

    .line 29
    .line 30
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-direct {v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    invoke-direct {v1, v4, v5, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 64
    .line 65
    .line 66
    invoke-direct {v0, v2, v3, v1}, Lcom/google/android/filament/utils/Mat3;-><init>(Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;Lcom/google/android/filament/utils/Float3;)V

    .line 67
    .line 68
    .line 69
    return-object v0
.end method

.method public final getW()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getX()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getY()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getZ()Lcom/google/android/filament/utils/Float4;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->hashCode()I

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
    iget-object v0, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 19
    .line 20
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v1

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 28
    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-int/2addr p0, v0

    .line 34
    return p0
.end method

.method public final inc()Lcom/google/android/filament/utils/Mat4;
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->inc()Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iput-object v2, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 10
    .line 11
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 12
    .line 13
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->inc()Lcom/google/android/filament/utils/Float4;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iput-object v3, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 18
    .line 19
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 20
    .line 21
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->inc()Lcom/google/android/filament/utils/Float4;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    iput-object v4, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 26
    .line 27
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 28
    .line 29
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->inc()Lcom/google/android/filament/utils/Float4;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    iput-object v5, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 34
    .line 35
    invoke-direct {v0, v1, v2, v3, v4}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 36
    .line 37
    .line 38
    return-object v0
.end method

.method public final invoke(II)F
    .locals 0

    add-int/lit8 p2, p2, -0x1

    .line 1
    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/Mat4;->get(I)Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->get(I)F

    move-result p0

    return p0
.end method

.method public final invoke(IIF)V
    .locals 0

    add-int/lit8 p2, p2, -0x1

    add-int/lit8 p1, p1, -0x1

    .line 2
    invoke-virtual {p0, p2, p1, p3}, Lcom/google/android/filament/utils/Mat4;->set(IIF)V

    return-void
.end method

.method public final minus(F)Lcom/google/android/filament/utils/Mat4;
    .locals 8

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    sub-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    sub-float/2addr v4, p1

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    sub-float/2addr v5, p1

    .line 22
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    sub-float/2addr v1, p1

    .line 27
    invoke-direct {v2, v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 31
    .line 32
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 33
    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    sub-float/2addr v4, p1

    .line 39
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    sub-float/2addr v5, p1

    .line 44
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    sub-float/2addr v6, p1

    .line 49
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    sub-float/2addr v1, p1

    .line 54
    invoke-direct {v3, v4, v5, v6, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 58
    .line 59
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 60
    .line 61
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    sub-float/2addr v5, p1

    .line 66
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    sub-float/2addr v6, p1

    .line 71
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    sub-float/2addr v7, p1

    .line 76
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    sub-float/2addr v1, p1

    .line 81
    invoke-direct {v4, v5, v6, v7, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 85
    .line 86
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 87
    .line 88
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    sub-float/2addr v5, p1

    .line 93
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    sub-float/2addr v6, p1

    .line 98
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    sub-float/2addr v7, p1

    .line 103
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    sub-float/2addr p0, p1

    .line 108
    invoke-direct {v1, v5, v6, v7, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 109
    .line 110
    .line 111
    invoke-direct {v0, v2, v3, v4, v1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 112
    .line 113
    .line 114
    return-object v0
.end method

.method public final plus(F)Lcom/google/android/filament/utils/Mat4;
    .locals 8

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    add-float/2addr v3, p1

    .line 12
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    add-float/2addr v4, p1

    .line 17
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    add-float/2addr v5, p1

    .line 22
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    add-float/2addr v1, p1

    .line 27
    invoke-direct {v2, v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 31
    .line 32
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 33
    .line 34
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    add-float/2addr v4, p1

    .line 39
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    add-float/2addr v5, p1

    .line 44
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    add-float/2addr v6, p1

    .line 49
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    add-float/2addr v1, p1

    .line 54
    invoke-direct {v3, v4, v5, v6, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 55
    .line 56
    .line 57
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 58
    .line 59
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 60
    .line 61
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    add-float/2addr v5, p1

    .line 66
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    add-float/2addr v6, p1

    .line 71
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    add-float/2addr v7, p1

    .line 76
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    add-float/2addr v1, p1

    .line 81
    invoke-direct {v4, v5, v6, v7, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 85
    .line 86
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 87
    .line 88
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    add-float/2addr v5, p1

    .line 93
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    add-float/2addr v6, p1

    .line 98
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    add-float/2addr v7, p1

    .line 103
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    add-float/2addr p0, p1

    .line 108
    invoke-direct {v1, v5, v6, v7, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 109
    .line 110
    .line 111
    invoke-direct {v0, v2, v3, v4, v1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 112
    .line 113
    .line 114
    return-object v0
.end method

.method public final set(IIF)V
    .locals 0

    .line 6
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat4;->get(I)Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    invoke-virtual {p0, p2, p3}, Lcom/google/android/filament/utils/Float4;->set(IF)V

    return-void
.end method

.method public final set(ILcom/google/android/filament/utils/Float4;)V
    .locals 1

    const-string v0, "v"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Mat4;->get(I)Lcom/google/android/filament/utils/Float4;

    move-result-object p0

    .line 2
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setX(F)V

    .line 3
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setY(F)V

    .line 4
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setZ(F)V

    .line 5
    invoke-virtual {p2}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setW(F)V

    return-void
.end method

.method public final setForward(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getZ()Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setX(F)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setY(F)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setZ(F)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final setPosition(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getW()Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setX(F)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setY(F)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setZ(F)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final setRight(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getX()Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setX(F)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setY(F)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setZ(F)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final setUp(Lcom/google/android/filament/utils/Float3;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Mat4;->getY()Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setX(F)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-virtual {p0, v0}, Lcom/google/android/filament/utils/Float4;->setY(F)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Float4;->setZ(F)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final setW(Lcom/google/android/filament/utils/Float4;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    return-void
.end method

.method public final setX(Lcom/google/android/filament/utils/Float4;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    return-void
.end method

.method public final setY(Lcom/google/android/filament/utils/Float4;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    return-void
.end method

.method public final setZ(Lcom/google/android/filament/utils/Float4;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 7
    .line 8
    return-void
.end method

.method public final times(Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Float4;
    .locals 6

    const-string v0, "v"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 164
    new-instance v0, Lcom/google/android/filament/utils/Float4;

    .line 165
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    mul-float/2addr v2, v1

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v1

    .line 166
    invoke-static {p1, v1, v2}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v1

    .line 167
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    .line 168
    invoke-static {p1, v2, v1}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v1

    .line 169
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    .line 170
    invoke-static {p1, v2, v1}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v1

    .line 171
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    mul-float/2addr v3, v2

    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v2

    .line 172
    invoke-static {p1, v2, v3}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v2

    .line 173
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v3

    .line 174
    invoke-static {p1, v3, v2}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v2

    .line 175
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v3

    .line 176
    invoke-static {p1, v3, v2}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v2

    .line 177
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v3

    .line 178
    invoke-static {p1, v3, v4}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 179
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v4

    .line 180
    invoke-static {p1, v4, v3}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 181
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v4

    .line 182
    invoke-static {p1, v4, v3}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 183
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v4

    .line 184
    invoke-static {p1, v4, v5}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 185
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v5

    .line 186
    invoke-static {p1, v5, v4}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 187
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    .line 188
    invoke-static {p1, p0, v4}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result p0

    .line 189
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    return-object v0
.end method

.method public final times(F)Lcom/google/android/filament/utils/Mat4;
    .locals 8

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 2
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    mul-float/2addr v3, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    mul-float/2addr v4, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    mul-float/2addr v5, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-direct {v2, v3, v4, v5, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 4
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    mul-float/2addr v4, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    mul-float/2addr v5, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    mul-float/2addr v6, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-direct {v3, v4, v5, v6, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 5
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 6
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    mul-float/2addr v5, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    mul-float/2addr v6, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    mul-float/2addr v7, p1

    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v1

    mul-float/2addr v1, p1

    invoke-direct {v4, v5, v6, v7, v1}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 7
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 8
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    mul-float/2addr v5, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    mul-float/2addr v6, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    mul-float/2addr v7, p1

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    mul-float/2addr p0, p1

    invoke-direct {v1, v5, v6, v7, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 9
    invoke-direct {v0, v2, v3, v4, v1}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-object v0
.end method

.method public final times(Lcom/google/android/filament/utils/Mat4;)Lcom/google/android/filament/utils/Mat4;
    .locals 11

    const-string v0, "m"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 11
    new-instance v1, Lcom/google/android/filament/utils/Float4;

    .line 12
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    iget-object v3, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    mul-float/2addr v3, v2

    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 13
    invoke-static {v4, v2, v3}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v2

    .line 14
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 15
    invoke-static {v4, v3, v2}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v2

    .line 16
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 17
    invoke-static {v4, v3, v2}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v2

    .line 18
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v3

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 19
    invoke-static {v5, v3, v4}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 20
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 21
    invoke-static {v5, v4, v3}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 22
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 23
    invoke-static {v5, v4, v3}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 24
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v4

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 25
    invoke-static {v6, v4, v5}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 26
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 27
    invoke-static {v6, v5, v4}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 28
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 29
    invoke-static {v6, v5, v4}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 30
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    mul-float/2addr v6, v5

    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v5

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 31
    invoke-static {v7, v5, v6}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 32
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 33
    invoke-static {v7, v6, v5}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 34
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 35
    invoke-static {v7, v6, v5}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 36
    invoke-direct {v1, v2, v3, v4, v5}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 37
    new-instance v2, Lcom/google/android/filament/utils/Float4;

    .line 38
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    iget-object v4, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    mul-float/2addr v4, v3

    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v3

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 39
    invoke-static {v5, v3, v4}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 40
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 41
    invoke-static {v5, v4, v3}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 42
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 43
    invoke-static {v5, v4, v3}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v3

    .line 44
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v4

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 45
    invoke-static {v6, v4, v5}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 46
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 47
    invoke-static {v6, v5, v4}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 48
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 49
    invoke-static {v6, v5, v4}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 50
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    mul-float/2addr v6, v5

    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v5

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 51
    invoke-static {v7, v5, v6}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 52
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 53
    invoke-static {v7, v6, v5}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 54
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 55
    invoke-static {v7, v6, v5}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 56
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v7

    mul-float/2addr v7, v6

    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v6

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 57
    invoke-static {v8, v6, v7}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 58
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 59
    invoke-static {v8, v7, v6}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 60
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 61
    invoke-static {v8, v7, v6}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 62
    invoke-direct {v2, v3, v4, v5, v6}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 63
    new-instance v3, Lcom/google/android/filament/utils/Float4;

    .line 64
    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    iget-object v5, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    mul-float/2addr v5, v4

    iget-object v4, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v4

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 65
    invoke-static {v6, v4, v5}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 66
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 67
    invoke-static {v6, v5, v4}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 68
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 69
    invoke-static {v6, v5, v4}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v4

    .line 70
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    mul-float/2addr v6, v5

    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 71
    invoke-static {v7, v5, v6}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 72
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 73
    invoke-static {v7, v6, v5}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 74
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 75
    invoke-static {v7, v6, v5}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 76
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v7

    mul-float/2addr v7, v6

    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 77
    invoke-static {v8, v6, v7}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 78
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 79
    invoke-static {v8, v7, v6}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 80
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 81
    invoke-static {v8, v7, v6}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 82
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v8

    mul-float/2addr v8, v7

    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v7

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 83
    invoke-static {v9, v7, v8}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v7

    .line 84
    iget-object v8, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v8

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 85
    invoke-static {v9, v8, v7}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v7

    .line 86
    iget-object v8, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v8

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 87
    invoke-static {v9, v8, v7}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v7

    .line 88
    invoke-direct {v3, v4, v5, v6, v7}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 89
    new-instance v4, Lcom/google/android/filament/utils/Float4;

    .line 90
    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    iget-object v6, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    mul-float/2addr v6, v5

    iget-object v5, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v5

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 91
    invoke-static {v7, v5, v6}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 92
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 93
    invoke-static {v7, v6, v5}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 94
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 95
    invoke-static {v7, v6, v5}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v5

    .line 96
    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    iget-object v7, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v7

    mul-float/2addr v7, v6

    iget-object v6, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v6

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 97
    invoke-static {v8, v6, v7}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 98
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 99
    invoke-static {v8, v7, v6}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 100
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 101
    invoke-static {v8, v7, v6}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v6

    .line 102
    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    iget-object v8, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v8

    mul-float/2addr v8, v7

    iget-object v7, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v7

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 103
    invoke-static {v9, v7, v8}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v7

    .line 104
    iget-object v8, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 105
    invoke-static {v9, v8, v7}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v7

    .line 106
    iget-object v8, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v8

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 107
    invoke-static {v9, v8, v7}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v7

    .line 108
    iget-object v8, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v8

    iget-object v9, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v9}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v9

    mul-float/2addr v9, v8

    iget-object v8, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v8

    iget-object v10, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 109
    invoke-static {v10, v8, v9}, Lc1/j0;->p(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v8

    .line 110
    iget-object v9, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {v9}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result v9

    iget-object v10, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 111
    invoke-static {v10, v9, v8}, Lc1/j0;->t(Lcom/google/android/filament/utils/Float4;FF)F

    move-result v8

    .line 112
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p0

    iget-object p1, p1, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 113
    invoke-static {p1, p0, v8}, Lc1/j0;->f(Lcom/google/android/filament/utils/Float4;FF)F

    move-result p0

    .line 114
    invoke-direct {v4, v5, v6, v7, p0}, Lcom/google/android/filament/utils/Float4;-><init>(FFFF)V

    .line 115
    invoke-direct {v0, v1, v2, v3, v4}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    return-object v0
.end method

.method public final toEulerAngles(Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;
    .locals 1

    .line 1
    const-string v0, "order"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/MatrixKt;->eulerAngles(Lcom/google/android/filament/utils/Mat4;Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final toFloatArray()[F
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget-object v2, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 10
    .line 11
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    iget-object v3, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 16
    .line 17
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    iget-object v4, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 22
    .line 23
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    iget-object v5, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 28
    .line 29
    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    iget-object v6, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 34
    .line 35
    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    iget-object v7, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 40
    .line 41
    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    iget-object v8, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 46
    .line 47
    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 48
    .line 49
    .line 50
    move-result v8

    .line 51
    iget-object v9, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 52
    .line 53
    invoke-virtual {v9}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 54
    .line 55
    .line 56
    move-result v9

    .line 57
    iget-object v10, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 58
    .line 59
    invoke-virtual {v10}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 60
    .line 61
    .line 62
    move-result v10

    .line 63
    iget-object v11, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 64
    .line 65
    invoke-virtual {v11}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 66
    .line 67
    .line 68
    move-result v11

    .line 69
    iget-object v12, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 70
    .line 71
    invoke-virtual {v12}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 72
    .line 73
    .line 74
    move-result v12

    .line 75
    iget-object v13, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 76
    .line 77
    invoke-virtual {v13}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 78
    .line 79
    .line 80
    move-result v13

    .line 81
    iget-object v14, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 82
    .line 83
    invoke-virtual {v14}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 84
    .line 85
    .line 86
    move-result v14

    .line 87
    iget-object v15, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 88
    .line 89
    invoke-virtual {v15}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 90
    .line 91
    .line 92
    move-result v15

    .line 93
    iget-object v0, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 94
    .line 95
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    move/from16 p0, v0

    .line 100
    .line 101
    const/16 v0, 0x10

    .line 102
    .line 103
    new-array v0, v0, [F

    .line 104
    .line 105
    const/16 v16, 0x0

    .line 106
    .line 107
    aput v1, v0, v16

    .line 108
    .line 109
    const/4 v1, 0x1

    .line 110
    aput v2, v0, v1

    .line 111
    .line 112
    const/4 v1, 0x2

    .line 113
    aput v3, v0, v1

    .line 114
    .line 115
    const/4 v1, 0x3

    .line 116
    aput v4, v0, v1

    .line 117
    .line 118
    const/4 v1, 0x4

    .line 119
    aput v5, v0, v1

    .line 120
    .line 121
    const/4 v1, 0x5

    .line 122
    aput v6, v0, v1

    .line 123
    .line 124
    const/4 v1, 0x6

    .line 125
    aput v7, v0, v1

    .line 126
    .line 127
    const/4 v1, 0x7

    .line 128
    aput v8, v0, v1

    .line 129
    .line 130
    const/16 v1, 0x8

    .line 131
    .line 132
    aput v9, v0, v1

    .line 133
    .line 134
    const/16 v1, 0x9

    .line 135
    .line 136
    aput v10, v0, v1

    .line 137
    .line 138
    const/16 v1, 0xa

    .line 139
    .line 140
    aput v11, v0, v1

    .line 141
    .line 142
    const/16 v1, 0xb

    .line 143
    .line 144
    aput v12, v0, v1

    .line 145
    .line 146
    const/16 v1, 0xc

    .line 147
    .line 148
    aput v13, v0, v1

    .line 149
    .line 150
    const/16 v1, 0xd

    .line 151
    .line 152
    aput v14, v0, v1

    .line 153
    .line 154
    const/16 v1, 0xe

    .line 155
    .line 156
    aput v15, v0, v1

    .line 157
    .line 158
    const/16 v1, 0xf

    .line 159
    .line 160
    aput p0, v0, v1

    .line 161
    .line 162
    return-object v0
.end method

.method public final toQuaternion()Lcom/google/android/filament/utils/Quaternion;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/MatrixKt;->quaternion(Lcom/google/android/filament/utils/Mat4;)Lcom/google/android/filament/utils/Quaternion;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget-object v2, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 10
    .line 11
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    iget-object v3, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 16
    .line 17
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    iget-object v4, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 22
    .line 23
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float4;->getX()F

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    iget-object v5, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 28
    .line 29
    invoke-virtual {v5}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    iget-object v6, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 34
    .line 35
    invoke-virtual {v6}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    iget-object v7, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 40
    .line 41
    invoke-virtual {v7}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    iget-object v8, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 46
    .line 47
    invoke-virtual {v8}, Lcom/google/android/filament/utils/Float4;->getY()F

    .line 48
    .line 49
    .line 50
    move-result v8

    .line 51
    iget-object v9, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 52
    .line 53
    invoke-virtual {v9}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 54
    .line 55
    .line 56
    move-result v9

    .line 57
    iget-object v10, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 58
    .line 59
    invoke-virtual {v10}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 60
    .line 61
    .line 62
    move-result v10

    .line 63
    iget-object v11, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 64
    .line 65
    invoke-virtual {v11}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 66
    .line 67
    .line 68
    move-result v11

    .line 69
    iget-object v12, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 70
    .line 71
    invoke-virtual {v12}, Lcom/google/android/filament/utils/Float4;->getZ()F

    .line 72
    .line 73
    .line 74
    move-result v12

    .line 75
    iget-object v13, v0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 76
    .line 77
    invoke-virtual {v13}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 78
    .line 79
    .line 80
    move-result v13

    .line 81
    iget-object v14, v0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 82
    .line 83
    invoke-virtual {v14}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 84
    .line 85
    .line 86
    move-result v14

    .line 87
    iget-object v15, v0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 88
    .line 89
    invoke-virtual {v15}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 90
    .line 91
    .line 92
    move-result v15

    .line 93
    iget-object v0, v0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 94
    .line 95
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float4;->getW()F

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    move/from16 p0, v0

    .line 100
    .line 101
    new-instance v0, Ljava/lang/StringBuilder;

    .line 102
    .line 103
    move/from16 v16, v15

    .line 104
    .line 105
    const-string v15, "\n            |"

    .line 106
    .line 107
    invoke-direct {v0, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, " "

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v2, "|\n            |"

    .line 134
    .line 135
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v0, v12}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 190
    .line 191
    .line 192
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    move/from16 v2, v16

    .line 199
    .line 200
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    move/from16 v1, p0

    .line 207
    .line 208
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    const-string v1, "|\n            "

    .line 212
    .line 213
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    invoke-static {v0}, Lly0/q;->g(Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    return-object v0
.end method

.method public final unaryMinus()Lcom/google/android/filament/utils/Mat4;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Mat4;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/filament/utils/Mat4;->x:Lcom/google/android/filament/utils/Float4;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float4;->unaryMinus()Lcom/google/android/filament/utils/Float4;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object v2, p0, Lcom/google/android/filament/utils/Mat4;->y:Lcom/google/android/filament/utils/Float4;

    .line 10
    .line 11
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float4;->unaryMinus()Lcom/google/android/filament/utils/Float4;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    iget-object v3, p0, Lcom/google/android/filament/utils/Mat4;->z:Lcom/google/android/filament/utils/Float4;

    .line 16
    .line 17
    invoke-virtual {v3}, Lcom/google/android/filament/utils/Float4;->unaryMinus()Lcom/google/android/filament/utils/Float4;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    iget-object p0, p0, Lcom/google/android/filament/utils/Mat4;->w:Lcom/google/android/filament/utils/Float4;

    .line 22
    .line 23
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float4;->unaryMinus()Lcom/google/android/filament/utils/Float4;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method
