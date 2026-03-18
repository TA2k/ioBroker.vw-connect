.class Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/a;


# instance fields
.field private final arg$0:Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer;

.field private final arg$1:Z

.field private final arg$2:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer;ZLkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;->arg$0:Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer;

    .line 5
    .line 6
    iput-boolean p2, p0, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;->arg$1:Z

    .line 7
    .line 8
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;->arg$2:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;->arg$0:Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer;

    .line 2
    .line 3
    iget-boolean v1, p0, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;->arg$1:Z

    .line 4
    .line 5
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer$$Lambda$3;->arg$2:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;

    .line 6
    .line 7
    invoke-static {v0, v1, p0}, Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer;->accessor$MemberDeserializer$lambda3(Lkotlin/reflect/jvm/internal/impl/serialization/deserialization/MemberDeserializer;ZLkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;)Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
