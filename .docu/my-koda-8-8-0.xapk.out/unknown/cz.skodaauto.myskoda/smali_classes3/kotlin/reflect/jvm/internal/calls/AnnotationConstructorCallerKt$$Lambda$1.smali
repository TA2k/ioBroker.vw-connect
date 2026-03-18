.class Lkotlin/reflect/jvm/internal/calls/AnnotationConstructorCallerKt$$Lambda$1;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/a;


# instance fields
.field private final arg$0:Ljava/lang/Class;

.field private final arg$1:Ljava/util/Map;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Ljava/util/Map;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/calls/AnnotationConstructorCallerKt$$Lambda$1;->arg$0:Ljava/lang/Class;

    .line 5
    .line 6
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/calls/AnnotationConstructorCallerKt$$Lambda$1;->arg$1:Ljava/util/Map;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/calls/AnnotationConstructorCallerKt$$Lambda$1;->arg$0:Ljava/lang/Class;

    .line 2
    .line 3
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/calls/AnnotationConstructorCallerKt$$Lambda$1;->arg$1:Ljava/util/Map;

    .line 4
    .line 5
    invoke-static {v0, p0}, Lkotlin/reflect/jvm/internal/calls/AnnotationConstructorCallerKt;->accessor$AnnotationConstructorCallerKt$lambda1(Ljava/lang/Class;Ljava/util/Map;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
