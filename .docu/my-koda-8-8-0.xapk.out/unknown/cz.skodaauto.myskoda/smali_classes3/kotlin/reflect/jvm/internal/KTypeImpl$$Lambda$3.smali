.class Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/a;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/KTypeImpl;

.field private final arg$1:I

.field private final arg$2:Llx0/i;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/KTypeImpl;ILlx0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;->arg$0:Lkotlin/reflect/jvm/internal/KTypeImpl;

    .line 5
    .line 6
    iput p2, p0, Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;->arg$1:I

    .line 7
    .line 8
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;->arg$2:Llx0/i;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;->arg$0:Lkotlin/reflect/jvm/internal/KTypeImpl;

    .line 2
    .line 3
    iget v1, p0, Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;->arg$1:I

    .line 4
    .line 5
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/KTypeImpl$$Lambda$3;->arg$2:Llx0/i;

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lkotlin/reflect/jvm/internal/KTypeImpl;->accessor$KTypeImpl$lambda3(Lkotlin/reflect/jvm/internal/KTypeImpl;ILlx0/i;)Ljava/lang/reflect/Type;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
