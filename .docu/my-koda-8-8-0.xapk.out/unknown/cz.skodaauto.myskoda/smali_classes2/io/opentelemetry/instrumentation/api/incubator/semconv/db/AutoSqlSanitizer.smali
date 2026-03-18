.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Call;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Drop;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Select;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Alter;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Merge;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Create;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Delete;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;
    }
.end annotation


# static fields
.field private static final FROM_TABLE_REF_MAX_IDENTIFIERS:I = 0x3

.field private static final IN_STATEMENT_NORMALIZED:Ljava/lang/String; = "$1(?)"

.field private static final IN_STATEMENT_PATTERN:Ljava/util/regex/Pattern;

.field static final LIMIT:I = 0x8000

.field private static final YYEOF:I = -0x1

.field private static final YYINITIAL:I = 0x0

.field private static final ZZ_ACTION:[I

.field private static final ZZ_ACTION_PACKED_0:Ljava/lang/String; = "\u0001\u0000\u0001\u0001\u0001\u0002\u0001\u0001\u0001\u0003\u0001\u0001\u0001\u0004\u0001\u0005\u0002\u0001\u0001\u0006\u0001\u0001\u0002\u0007\u000f\u0008\u0001\u0001\u0001\u0000\u0001\t\u0001\u0000\u0001\u0003\u0001\u0000\u0001\u0007\u0001\n\u0001\u0000\u0001\u000b\u0002\u0000\u0008\u0008\u0001\u0001\n\u0008\u0001\u0000\u0001\u0003\u0001\u0000\u0001\u0007\u0002\u0000\u0013\u0008\u0001\u0007\u0003\u0008\u0001\u000c\u0003\u0008\u0001\r\u0001\u0008\u0001\u000e\u0002\u0008\u0001\u000f\u0001\u0010\u0001\u0008\u0001\u0011\u0004\u0008\u0001\u0012\u0001\u0013\u0005\u0008\u0001\u0014\u0003\u0008\u0001\u0015\u0001\u0008\u0001\u0016\u0001\u0017\u0001\u0008\u0001\u0018\u0001\u0019\u0001\u0008"

.field private static final ZZ_ATTRIBUTE:[I

.field private static final ZZ_ATTRIBUTE_PACKED_0:Ljava/lang/String; = "\u0001\u0000\u0001\t\u0004\u0001\u0002\t\u0002\u0001\u0001\t\u0013\u0001\u0001\u0000\u0001\u0001\u0001\u0000\u0001\u0001\u0001\u0000\u0001\u0001\u0001\t\u0001\u0000\u0001\t\u0002\u0000\u0013\u0001\u0001\u0000\u0001\u0001\u0001\u0000\u0001\u0001\u0002\u0000\u0013\u0001\u0001\t\'\u0001"

.field private static final ZZ_BUFFERSIZE:I = 0x800

.field private static final ZZ_CMAP_BLOCKS:[I

.field private static final ZZ_CMAP_BLOCKS_PACKED_0:Ljava/lang/String; = "\t\u0000\u0002\u0001\u0002\u0000\u0001\u0001\u0012\u0000\u0001\u0001\u0001\u0000\u0001\u0002\u0001\u0000\u0001\u0003\u0002\u0000\u0001\u0004\u0001\u0005\u0001\u0006\u0001\u0007\u0001\u0008\u0001\t\u0001\u0008\u0001\n\u0001\u000b\u0001\u000c\t\r\u0007\u0000\u0001\u000e\u0001\u000f\u0001\u0010\u0001\u0011\u0001\u0012\u0001\u0013\u0001\u0014\u0001\u0015\u0001\u0016\u0001\u0017\u0001\u0015\u0001\u0018\u0001\u0019\u0001\u001a\u0001\u001b\u0001\u001c\u0001\u0015\u0001\u001d\u0001\u001e\u0001\u001f\u0001 \u0001!\u0001\"\u0001#\u0002\u0015\u0004\u0000\u0001\u0015\u0001$\u0001\u000e\u0001\u000f\u0001\u0010\u0001\u0011\u0001\u0012\u0001\u0013\u0001\u0014\u0001\u0015\u0001\u0016\u0001\u0017\u0001\u0015\u0001\u0018\u0001\u0019\u0001\u001a\u0001\u001b\u0001\u001c\u0001\u0015\u0001\u001d\u0001\u001e\u0001\u001f\u0001 \u0001!\u0001\"\u0001#\u0002\u0015/\u0000\u0001\u0015\n\u0000\u0001\u0015\u0004\u0000\u0001\u0015\u0005\u0000\u0017\u0015\u0001\u0000\u001f\u0015\u0001\u00008\u0015\u0002\u0016M\u0015\u0001\u001e\u0142\u0015\u0004\u0000\u000c\u0015\u000e\u0000\u0005\u0015\u0007\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0081\u0000\u0005\u0015\u0001\u0000\u0002\u0015\u0002\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0006\u0000\u0001\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0014\u0015\u0001\u0000S\u0015\u0001\u0000\u008b\u0015\u0008\u0000\u00a6\u0015\u0001\u0000&\u0015\u0002\u0000\u0001\u0015\u0006\u0000)\u0015G\u0000\u001b\u0015\u0004\u0000\u0004\u0015-\u0000+\u0015#\u0000\u0002\u0015\u0001\u0000c\u0015\u0001\u0000\u0001\u0015\u000f\u0000\u0002\u0015\u0007\u0000\u0002\u0015\n\u0000\u0003\u0015\u0002\u0000\u0001\u0015\u0010\u0000\u0001\u0015\u0001\u0000\u001e\u0015\u001d\u0000Y\u0015\u000b\u0000\u0001\u0015\u0018\u0000!\u0015\t\u0000\u0002\u0015\u0004\u0000\u0001\u0015\u0005\u0000\u0016\u0015\u0004\u0000\u0001\u0015\t\u0000\u0001\u0015\u0003\u0000\u0001\u0015\u0017\u0000\u0019\u0015\u0007\u0000\u000b\u00155\u0000\u0015\u0015\u0001\u0000\u0008\u0015F\u00006\u0015\u0003\u0000\u0001\u0015\u0012\u0000\u0001\u0015\u0007\u0000\n\u0015\u000f\u0000\u0010\u0015\u0004\u0000\u0008\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0004\u0015\u0003\u0000\u0001\u0015\u0010\u0000\u0001\u0015\r\u0000\u0002\u0015\u0001\u0000\u0003\u0015\u000e\u0000\u0002\u0015\n\u0000\u0001\u0015\u0008\u0000\u0006\u0015\u0004\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0002\u0015\u001f\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0013\u0000\u0003\u0015\u0010\u0000\t\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015\u0012\u0000\u0001\u0015\u000f\u0000\u0002\u0015\u0017\u0000\u0001\u0015\u000b\u0000\u0008\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015\u001e\u0000\u0002\u0015\u0001\u0000\u0003\u0015\u000f\u0000\u0001\u0015\u0011\u0000\u0001\u0015\u0001\u0000\u0006\u0015\u0003\u0000\u0003\u0015\u0001\u0000\u0004\u0015\u0003\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u0003\u0000\u0002\u0015\u0003\u0000\u0003\u0015\u0003\u0000\u000c\u0015\u0016\u0000\u0001\u00154\u0000\u0008\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0017\u0015\u0001\u0000\u0010\u0015\u0003\u0000\u0001\u0015\u001a\u0000\u0003\u0015\u0005\u0000\u0002\u0015\u001e\u0000\u0001\u0015\u0004\u0000\u0008\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0017\u0015\u0001\u0000\n\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015 \u0000\u0001\u0015\u0001\u0000\u0002\u0015\u000f\u0000\u0002\u0015\u0012\u0000\u0008\u0015\u0001\u0000\u0003\u0015\u0001\u0000)\u0015\u0002\u0000\u0001\u0015\u0010\u0000\u0001\u0015\u0005\u0000\u0003\u0015\u0008\u0000\u0003\u0015\u0018\u0000\u0006\u0015\u0005\u0000\u0012\u0015\u0003\u0000\u0018\u0015\u0001\u0000\t\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0007\u0015:\u00000\u0015\u0001\u0000\u0002\u0015\u000c\u0000\u0007\u0015:\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0018\u0015\u0001\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\u0002\u0015\t\u0000\u0001\u0015\u0002\u0000\u0005\u0015\u0001\u0000\u0001\u0015\u0015\u0000\u0004\u0015 \u0000\u0001\u0015?\u0000\u0008\u0015\u0001\u0000$\u0015\u001b\u0000\u0005\u0015s\u0000+\u0015\u0014\u0000\u0001\u0015\u0010\u0000\u0006\u0015\u0004\u0000\u0004\u0015\u0003\u0000\u0001\u0015\u0003\u0000\u0002\u0015\u0007\u0000\u0003\u0015\u0004\u0000\r\u0015\u000c\u0000\u0001\u0015\u0011\u0000&\u0015\u0001\u0000\u0001\u0015\u0005\u0000\u0001\u0015\u0002\u0000+\u0015\u0001\u0000\u014d\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0002\u0000)\u0015\u0001\u0000\u0004\u0015\u0002\u0000!\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u000f\u0015\u0001\u00009\u0015\u0001\u0000\u0004\u0015\u0002\u0000C\u0015%\u0000\u0010\u0015\u0010\u0000V\u0015\u0002\u0000\u0006\u0015\u0003\u0000\u016c\u0015\u0002\u0000\u0011\u0015\u0001\u0000\u001a\u0015\u0005\u0000K\u0015\u0006\u0000\u0008\u0015\u0007\u0000\r\u0015\u0001\u0000\u0004\u0015\u000e\u0000\u0012\u0015\u000e\u0000\u0012\u0015\u000e\u0000\r\u0015\u0001\u0000\u0003\u0015\u000f\u00004\u0015#\u0000\u0001\u0015\u0004\u0000\u0001\u0015C\u0000Y\u0015\u0007\u0000\u0005\u0015\u0002\u0000\"\u0015\u0001\u0000\u0001\u0015\u0005\u0000F\u0015\n\u0000\u001f\u00151\u0000\u001e\u0015\u0002\u0000\u0005\u0015\u000b\u0000,\u0015\u0004\u0000\u001a\u00156\u0000\u0017\u0015\t\u00005\u0015R\u0000\u0001\u0015]\u0000/\u0015\u0011\u0000\u0007\u00157\u0000\u001e\u0015\r\u0000\u0002\u0015\n\u0000,\u0015\u001a\u0000$\u0015)\u0000\u0003\u0015\n\u0000$\u0015\u0002\u0000\t\u0015\u0007\u0000+\u0015\u0002\u0000\u0003\u0015)\u0000\u0004\u0015\u0001\u0000\u0006\u0015\u0001\u0000\u0002\u0015\u0003\u0000\u0001\u0015\u0005\u0000\u00c0\u0015@\u0000\u0016\u0015\u0002\u0000\u0006\u0015\u0002\u0000&\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0008\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u001f\u0015\u0002\u00005\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0003\u0015\u0001\u0000\u0007\u0015\u0003\u0000\u0004\u0015\u0002\u0000\u0006\u0015\u0004\u0000\r\u0015\u0005\u0000\u0003\u0015\u0001\u0000\u0007\u0015t\u0000\u0001\u0015\r\u0000\u0001\u0015\u0010\u0000\r\u0015e\u0000\u0001\u0015\u0004\u0000\u0001\u0015\u0002\u0000\n\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0005\u0015\u0006\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u000b\u0015\u0002\u0000\u0004\u0015\u0005\u0000\u0005\u0015\u0004\u0000\u0001\u00154\u0000\u0002\u0015\u017b\u0000/\u0015\u0001\u0000/\u0015\u0001\u0000\u0085\u0015\u0006\u0000\u0004\u0015\u0003\u0000\u0002\u0015\u000c\u0000&\u0015\u0001\u0000\u0001\u0015\u0005\u0000\u0001\u0015\u0002\u00008\u0015\u0007\u0000\u0001\u0015\u0010\u0000\u0017\u0015\t\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015P\u0000\u0001\u0015\u00d5\u0000\u0002\u0015*\u0000\u0005\u0015\u0005\u0000\u0002\u0015\u0004\u0000V\u0015\u0006\u0000\u0003\u0015\u0001\u0000Z\u0015\u0001\u0000\u0004\u0015\u0005\u0000+\u0015\u0001\u0000^\u0015\u0011\u0000\u001b\u00155\u0000\u00c6\u0015J\u0000\u00f0\u0015\u0010\u0000\u008d\u0015C\u0000.\u0015\u0002\u0000\r\u0015\u0003\u0000\u0010\u0015\n\u0000\u0002\u0015\u0014\u0000/\u0015\u0010\u0000\u001f\u0015\u0002\u0000F\u00151\u0000\t\u0015\u0002\u0000g\u0015\u0002\u00005\u0015\u0002\u0000\u0005\u00150\u0000\u000b\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0017\u0015\u001d\u00004\u0015\u000e\u00002\u0015>\u0000\u0006\u0015\u0003\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u000b\u0000\u001c\u0015\n\u0000\u0017\u0015\u0019\u0000\u001d\u0015\u0007\u0000/\u0015\u001c\u0000\u0001\u0015\u0010\u0000\u0005\u0015\u0001\u0000\n\u0015\n\u0000\u0005\u0015\u0001\u0000)\u0015\u0017\u0000\u0003\u0015\u0001\u0000\u0008\u0015\u0014\u0000\u0017\u0015\u0003\u0000\u0001\u0015\u0003\u00002\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0002\u0015\u0002\u0000\u0005\u0015\u0002\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0018\u0000\u0003\u0015\u0002\u0000\u000b\u0015\u0007\u0000\u0003\u0015\u000c\u0000\u0006\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0006\u0015\t\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000+\u0015\u0001\u0000\u000c\u0015\u0008\u0000s\u0015\u001d\u0000\u00a4\u0015\u000c\u0000\u0017\u0015\u0004\u00001\u0015\u0004\u0000n\u0015\u0002\u0000j\u0015&\u0000\u0007\u0015\u000c\u0000\u0005\u0015\u0005\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\r\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0002\u0015\u0001\u0000l\u0015!\u0000k\u0015\u0012\u0000@\u0015\u0002\u00006\u0015(\u0000\u000c\u0015t\u0000\u0005\u0015\u0001\u0000\u0087\u0015$\u0000\u001a\u0015\u0006\u0000\u001a\u0015\u000b\u0000Y\u0015\u0003\u0000\u0006\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0003\u0015#\u0000\u000c\u0015\u0001\u0000\u001a\u0015\u0001\u0000\u0013\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u000f\u0015\u0002\u0000\u000e\u0015\"\u0000{\u0015\u0085\u0000\u001d\u0015\u0003\u00001\u0015/\u0000 \u0015\r\u0000\u0014\u0015\u0001\u0000\u0008\u0015\u0006\u0000&\u0015\n\u0000\u001e\u0015\u0002\u0000$\u0015\u0004\u0000\u0008\u00150\u0000\u009e\u0015\u0012\u0000$\u0015\u0004\u0000$\u0015\u0004\u0000(\u0015\u0008\u00004\u0015\u009c\u00007\u0015\t\u0000\u0016\u0015\n\u0000\u0008\u0015\u0098\u0000\u0006\u0015\u0002\u0000\u0001\u0015\u0001\u0000,\u0015\u0001\u0000\u0002\u0015\u0003\u0000\u0001\u0015\u0002\u0000\u0017\u0015\n\u0000\u0017\u0015\t\u0000\u001f\u0015A\u0000\u0013\u0015\u0001\u0000\u0002\u0015\n\u0000\u0016\u0015\n\u0000\u001a\u0015F\u00008\u0015\u0006\u0000\u0002\u0015@\u0000\u0001\u0015\u000f\u0000\u0004\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u001d\u0015*\u0000\u001d\u0015\u0003\u0000\u001d\u0015#\u0000\u0008\u0015\u0001\u0000\u001c\u0015\u001b\u00006\u0015\n\u0000\u0016\u0015\n\u0000\u0013\u0015\r\u0000\u0012\u0015n\u0000I\u00157\u00003\u0015\r\u00003\u0015\r\u0000$\u0015\u00dc\u0000\u001d\u0015\n\u0000\u0001\u0015\u0008\u0000\u0016\u0015\u009a\u0000\u0017\u0015\u000c\u00005\u0015K\u0000-\u0015 \u0000\u0019\u0015\u001a\u0000$\u0015\u001d\u0000\u0001\u0015\u000b\u0000#\u0015\u0003\u0000\u0001\u0015\u000c\u00000\u0015\u000e\u0000\u0004\u0015\u0015\u0000\u0001\u0015\u0001\u0000\u0001\u0015#\u0000\u0012\u0015\u0001\u0000\u0019\u0015T\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u000f\u0015\u0001\u0000\n\u0015\u0007\u0000/\u0015&\u0000\u0008\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015\u0012\u0000\u0001\u0015\u000c\u0000\u0005\u0015\u009e\u00005\u0015\u0012\u0000\u0004\u0015\u0014\u0000\u0001\u0015 \u00000\u0015\u0014\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u00b8\u0000/\u0015)\u0000\u0004\u0015$\u00000\u0015\u0014\u0000\u0001\u0015;\u0000+\u0015\r\u0000\u0001\u0015G\u0000\u001b\u0015\u00e5\u0000,\u0015t\u0000@\u0015\u001f\u0000\u0001\u0015\u00a0\u0000\u0008\u0015\u0002\u0000\'\u0015\u0010\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u001c\u0000\u0001\u0015\n\u0000(\u0015\u0007\u0000\u0001\u0015\u0015\u0000\u0001\u0015\u000b\u0000.\u0015\u0013\u0000\u0001\u0015\"\u00009\u0015\u0007\u0000\t\u0015\u0001\u0000%\u0015\u0011\u0000\u0001\u00151\u0000\u001e\u0015p\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000&\u0015\u0015\u0000\u0001\u0015\u0019\u0000\u0006\u0015\u0001\u0000\u0002\u0015\u0001\u0000 \u0015\u000e\u0000\u0001\u0015\u0147\u0000\u0013\u0015\r\u0000\u009a\u0015\u00e6\u0000\u00c4\u0015\u00bc\u0000/\u0015\u00d1\u0000G\u0015\u00b9\u00009\u0015\u0007\u0000\u001f\u0015q\u0000\u001e\u0015\u0012\u00000\u0015\u0010\u0000\u0004\u0015\u001f\u0000\u0015\u0015\u0005\u0000\u0013\u0015\u00b0\u0000@\u0015\u0080\u0000K\u0015\u0005\u0000\u0001\u0015B\u0000\r\u0015@\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u001c\u0000\u00f8\u0015\u0008\u0000\u00f3\u0015\r\u0000\u001f\u00151\u0000\u0003\u0015\u0011\u0000\u0004\u0015\u0008\u0000\u018c\u0015\u0004\u0000k\u0015\u0005\u0000\r\u0015\u0003\u0000\t\u0015\u0007\u0000\n\u0015f\u0000U\u0015\u0001\u0000G\u0015\u0001\u0000\u0002\u0015\u0002\u0000\u0001\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0004\u0015\u0001\u0000\u000c\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0007\u0015\u0001\u0000A\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u0008\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u001c\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0007\u0015\u0001\u0000\u0154\u0015\u0002\u0000\u0019\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u0008\u00154\u0000-\u0015\n\u0000\u0007\u0015\u0010\u0000\u0001\u0015\u0171\u0000,\u0015\u0014\u0000\u00c5\u0015;\u0000D\u0015\u0007\u0000\u0001\u0015\u00b4\u0000\u0004\u0015\u0001\u0000\u001b\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0006\u0000\u0001\u0015\u0004\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0004\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\u0011\u0015\u0005\u0000\u0003\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0011\u0015D\u0000\u00d7\u0015)\u00005\u0015\u000b\u0000\u00de\u0015\u0002\u0000\u0182\u0015\u000e\u0000\u0131\u0015\u001f\u0000\u001e\u0015\u00e2\u0000"

.field private static final ZZ_CMAP_TOP:[I

.field private static final ZZ_CMAP_TOP_PACKED_0:Ljava/lang/String; = "\u0001\u0000\u0001\u0100\u0001\u0200\u0001\u0300\u0001\u0400\u0001\u0500\u0001\u0600\u0001\u0700\u0001\u0800\u0001\u0900\u0001\u0a00\u0001\u0b00\u0001\u0c00\u0001\u0d00\u0001\u0e00\u0001\u0f00\u0001\u1000\u0001\u1100\u0001\u1200\u0001\u1300\u0001\u1400\u0001\u1100\u0001\u1500\u0001\u1600\u0001\u1700\u0001\u1800\u0001\u1900\u0001\u1a00\u0001\u1b00\u0001\u1c00\u0001\u1100\u0001\u1d00\u0001\u1e00\u0001\u1f00\n\u2000\u0001\u2100\u0001\u2200\u0001\u2300\u0001\u2000\u0001\u2400\u0001\u2500\u0002\u2000\u0019\u1100\u0001\u2600Q\u1100\u0001\u2700\u0004\u1100\u0001\u2800\u0001\u1100\u0001\u2900\u0001\u2a00\u0001\u2b00\u0001\u2c00\u0001\u2d00\u0001\u2e00+\u1100\u0001\u2f00!\u2000\u0001\u1100\u0001\u3000\u0001\u3100\u0001\u1100\u0001\u3200\u0001\u3300\u0001\u3400\u0001\u3500\u0001\u2000\u0001\u3600\u0001\u3700\u0001\u3800\u0001\u3900\u0001\u1100\u0001\u3a00\u0001\u3b00\u0001\u3c00\u0001\u3d00\u0001\u3e00\u0001\u3f00\u0001\u4000\u0001\u2000\u0001\u4100\u0001\u4200\u0001\u4300\u0001\u4400\u0001\u4500\u0001\u4600\u0001\u4700\u0001\u4800\u0001\u4900\u0001\u4a00\u0001\u4b00\u0001\u4c00\u0001\u2000\u0001\u4d00\u0001\u4e00\u0001\u4f00\u0001\u2000\u0003\u1100\u0001\u5000\u0001\u5100\u0001\u5200\n\u2000\u0004\u1100\u0001\u5300\u000f\u2000\u0002\u1100\u0001\u5400!\u2000\u0002\u1100\u0001\u5500\u0001\u5600\u0002\u2000\u0001\u5700\u0001\u5800\u0017\u1100\u0001\u5900\u0002\u1100\u0001\u5a00%\u2000\u0001\u1100\u0001\u5b00\u0001\u5c00\t\u2000\u0001\u5d00\u0017\u2000\u0001\u5e00\u0001\u5f00\u0001\u6000\u0001\u6100\t\u2000\u0001\u6200\u0001\u6300\u0005\u2000\u0001\u6400\u0001\u6500\u0004\u2000\u0001\u6600\u0011\u2000\u00a6\u1100\u0001\u6700\u0010\u1100\u0001\u6800\u0001\u6900\u0015\u1100\u0001\u6a00\u001c\u1100\u0001\u6b00\u000c\u2000\u0002\u1100\u0001\u6c00\u0e05\u2000"

.field private static final ZZ_ERROR_MSG:[Ljava/lang/String;

.field private static final ZZ_LEXSTATE:[I

.field private static final ZZ_NO_MATCH:I = 0x1

.field private static final ZZ_PUSHBACK_2BIG:I = 0x2

.field private static final ZZ_ROWMAP:[I

.field private static final ZZ_ROWMAP_PACKED_0:Ljava/lang/String; = "\u0000\u0000\u0000%\u0000J\u0000o\u0000\u0094\u0000\u00b9\u0000%\u0000%\u0000\u00de\u0000\u0103\u0000%\u0000\u0128\u0000\u014d\u0000\u0172\u0000\u0197\u0000\u01bc\u0000\u01e1\u0000\u0206\u0000\u022b\u0000\u0250\u0000\u0275\u0000\u029a\u0000\u02bf\u0000\u02e4\u0000\u0309\u0000\u032e\u0000\u0353\u0000\u0378\u0000\u039d\u0000\u03c2\u0000o\u0000\u03e7\u0000\u040c\u0000\u0431\u0000\u00b9\u0000\u0456\u0000%\u0000\u0103\u0000%\u0000\u047b\u0000\u04a0\u0000\u04c5\u0000\u04ea\u0000\u050f\u0000\u0534\u0000\u0559\u0000\u057e\u0000\u05a3\u0000\u05c8\u0000\u01bc\u0000\u05ed\u0000\u0612\u0000\u0637\u0000\u065c\u0000\u0681\u0000\u06a6\u0000\u06cb\u0000\u06f0\u0000\u0715\u0000\u073a\u0000\u03c2\u0000\u075f\u0000\u0784\u0000\u047b\u0000\u07a9\u0000\u07ce\u0000\u07f3\u0000\u0818\u0000\u083d\u0000\u0862\u0000\u0887\u0000\u08ac\u0000\u08d1\u0000\u08f6\u0000\u091b\u0000\u0940\u0000\u0965\u0000\u098a\u0000\u09af\u0000\u09d4\u0000\u09f9\u0000\u0a1e\u0000\u0a43\u0000\u0a68\u0000\u0a8d\u0000%\u0000\u0ab2\u0000\u075f\u0000\u0ad7\u0000\u01bc\u0000\u0afc\u0000\u0b21\u0000\u0b46\u0000\u01bc\u0000\u0b6b\u0000\u01bc\u0000\u0b90\u0000\u0bb5\u0000\u01bc\u0000\u01bc\u0000\u0bda\u0000\u01bc\u0000\u0bff\u0000\u0c24\u0000\u0c49\u0000\u0c6e\u0000\u01bc\u0000\u01bc\u0000\u0c93\u0000\u0cb8\u0000\u0cdd\u0000\u0d02\u0000\u0d27\u0000\u01bc\u0000\u0d4c\u0000\u0d71\u0000\u0d96\u0000\u01bc\u0000\u0dbb\u0000\u01bc\u0000\u01bc\u0000\u0de0\u0000\u01bc\u0000\u01bc\u0000\u0e05"

.field private static final ZZ_TRANS:[I

.field private static final ZZ_TRANS_PACKED_0:Ljava/lang/String; = "\u0001\u0002\u0001\u0003\u0001\u0004\u0001\u0005\u0001\u0006\u0001\u0007\u0001\u0008\u0001\t\u0001\n\u0001\u000b\u0001\n\u0001\u000c\u0001\r\u0001\u000e\u0001\u000f\u0001\u0010\u0001\u0011\u0001\u0012\u0001\u0013\u0001\u0014\u0002\u0010\u0001\u0015\u0001\u0016\u0001\u0010\u0001\u0017\u0001\u0018\u0001\u0010\u0001\u0019\u0001\u0010\u0001\u001a\u0001\u001b\u0001\u001c\u0001\u001d\u0002\u0010\u0001\u001e&\u0000\u0001\u0003#\u0000\u0002\u001f\u0001 \"\u001f\u0003\u0000\u0001!\u0008\u0000\u0002\"\u0017\u0000\u0004#\u0001$ #\u000b\u0000\u0001%!\u0000\u0001&\u0001\u0000\u0001&\u0001\u0000\u0002\u000e\u001e\u0000\u0001\'%\u0000\u0001\u000e\u0001\u0000\u0001\u000e\u0001\u0000\u0002\u000e\u0004\u0000\u0001\u000e\u0010\u0000\u0001(\t\u0000\u0001\u000e\u0001\u0000\u0001\u000e\u0001\u0000\u0002\u000e\u0004\u0000\u0001\u000e\u001c\u0000\u0001)\u0001\u0000\u000c\u0010\u0001*\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0018\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001+\u000e\u0010\u0001,\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001-\u0003\u0010\u0001.\n\u0010\u0001/\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0017\u0010\u00010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u00011\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0007\u0010\u00012\u0006\u0010\u00013\t\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u00014\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u00015\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u00016\u0008\u0010\u00017\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u00018\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u00019\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001:\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0010\u0010\u0001;\u0007\u0010\u000b\u0000\u0001)\u0001\u0000\n\u0010\u0001<\r\u0010\u0001\u0000$=\u0001>\u0002\u0000\u0001\u001f\u0007\u0000\u0001)\u001a\u0000\u0003!\u0001?!!\u000c\u0000\u0002\"\u001b\u0000\u0001#,\u0000\u0008@\u0013\u0000\u0001A\u000b\u0000\u0016\u0010\u0001B\n\u0000\u0001)\u0001\u0000\u0013\u0010\u0001C\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001D\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001E\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001F\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001G\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001H\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\n\u0010\u0001I\r\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001J\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u0005\u0010\u0001K\u000c\u0010\u0001L\u0001M\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\n\u0010\u0001N\r\u0010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u0001O\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0017\u0010\u0001P\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u00012\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001Q\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001R\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0003\u0010\u0001S\u0014\u0010\u000b\u0000\u0001)\u0001\u0000\u0005\u0010\u0001T\u0012\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001U\u0011\u0010\u000b\u0000\u0001)\u001d\u0000\u0001V!\u0000\u0002A\u0001W\"A$B\u0001X\n\u0000\u0001)\u0001\u0000\u0006\u0010\u0001Y\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001Z\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001[\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001\\\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001]\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0010\u0010\u0001^\u0007\u0010\u000b\u0000\u0001)\u0001\u0000\u0012\u0010\u0001_\u0005\u0010\u000b\u0000\u0001)\u0001\u0000\r\u0010\u0001`\n\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001a\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001b\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001c\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u000e\u0010\u0001d\t\u0010\u000b\u0000\u0001)\u0001\u0000\u0008\u0010\u0001e\u000f\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001f\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0004\u0010\u0001g\u0013\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001h\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001i\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001j\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0016\u0010\u0001k\u0001\u0010\u0003\u0000\u0001A\u0007\u0000\u0001)$\u0000\u0001)\u0001\u0000\u0011\u0010\u0001l\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001m\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0003\u0010\u0001n\u0014\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001o\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001p\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0017\u0010\u0001k\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u0001q\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001r\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001s\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0004\u0010\u0001t\u0013\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001k\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001u\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001v\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001w\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001x\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0012\u0010\u00012\u0005\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001y\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0005\u0010\u0001z\u0012\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001{\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001|\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0012\u0010\u0001i\u0005\u0010\u000b\u0000\u0001)\u0001\u0000\u0014\u0010\u0001}\u0003\u0010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u0001i\u0006\u0010\u0001\u0000"

.field private static final ZZ_UNKNOWN_ERROR:I


# instance fields
.field private final builder:Ljava/lang/StringBuilder;

.field private dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

.field private extractionDone:Z

.field private insideComment:Z

.field private operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

.field private parenLevel:I

.field private yychar:J

.field private yycolumn:I

.field private yyline:I

.field private zzAtBOL:Z

.field private zzAtEOF:Z

.field private zzBuffer:[C

.field private zzCurrentPos:I

.field private zzEOFDone:Z

.field private zzEndRead:I

.field private zzFinalHighSurrogate:I

.field private zzLexicalState:I

.field private zzMarkedPos:I

.field private zzReader:Ljava/io/Reader;

.field private zzStartRead:I

.field private zzState:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    filled-new-array {v0, v0}, [I

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_LEXSTATE:[I

    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackcmap_top()[I

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_CMAP_TOP:[I

    .line 13
    .line 14
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackcmap_blocks()[I

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_CMAP_BLOCKS:[I

    .line 19
    .line 20
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackAction()[I

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ACTION:[I

    .line 25
    .line 26
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackRowMap()[I

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ROWMAP:[I

    .line 31
    .line 32
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpacktrans()[I

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_TRANS:[I

    .line 37
    .line 38
    const-string v0, "Error: could not match input"

    .line 39
    .line 40
    const-string v1, "Error: pushback value was too large"

    .line 41
    .line 42
    const-string v2, "Unknown internal scanner error"

    .line 43
    .line 44
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ERROR_MSG:[Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackAttribute()[I

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ATTRIBUTE:[I

    .line 55
    .line 56
    const-string v0, "(\\sIN\\s*)\\(\\s*\\?\\s*(?:,\\s*\\?\\s*)*+\\)"

    .line 57
    .line 58
    const/4 v1, 0x2

    .line 59
    invoke-static {v0, v1}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->IN_STATEMENT_PATTERN:Ljava/util/regex/Pattern;

    .line 64
    .line 65
    return-void
.end method

.method public constructor <init>(Ljava/io/Reader;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzLexicalState:I

    .line 6
    .line 7
    const/16 v1, 0x800

    .line 8
    .line 9
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMaxBufferLen()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    new-array v1, v1, [C

    .line 18
    .line 19
    iput-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 20
    .line 21
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    iput-boolean v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtBOL:Z

    .line 25
    .line 26
    new-instance v1, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 32
    .line 33
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->parenLevel:I

    .line 34
    .line 35
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 36
    .line 37
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 38
    .line 39
    iput-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 40
    .line 41
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 42
    .line 43
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzReader:Ljava/io/Reader;

    .line 44
    .line 45
    return-void
.end method

.method public static synthetic access$100(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->readIdentifierName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic access$200(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->parenLevel:I

    .line 2
    .line 3
    return p0
.end method

.method private appendCurrentFragment()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 4
    .line 5
    iget v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 6
    .line 7
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 8
    .line 9
    sub-int/2addr p0, v2

    .line 10
    invoke-virtual {v0, v1, v2, p0}, Ljava/lang/StringBuilder;->append([CII)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method private getResult()Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0x8000

    .line 8
    .line 9
    .line 10
    if-le v0, v1, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->delete(II)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->IN_STATEMENT_PATTERN:Ljava/util/regex/Pattern;

    .line 28
    .line 29
    invoke-virtual {v1, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const-string v1, "$1(?)"

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->getResult(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method private isOverLimit()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->length()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const v0, 0x8000

    .line 8
    .line 9
    .line 10
    if-le p0, v0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method private readIdentifierName()Ljava/lang/String;
    .locals 3

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yytext()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    const-string v1, "\""

    .line 8
    .line 9
    invoke-direct {p0, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->removeQuotes(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    return-object v1

    .line 20
    :cond_0
    const-string v1, "`"

    .line 21
    .line 22
    invoke-direct {p0, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->removeQuotes(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_1

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_1
    return-object v0
.end method

.method private removeQuotes(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1, p2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1, p2}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    const/4 v0, 0x1

    .line 18
    sub-int/2addr p0, v0

    .line 19
    invoke-virtual {p1, v0, p0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0, p2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 24
    .line 25
    .line 26
    move-result p2

    .line 27
    if-nez p2, :cond_0

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_0
    return-object p1
.end method

.method public static sanitize(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    .line 2
    .line 3
    new-instance v1, Ljava/io/StringReader;

    .line 4
    .line 5
    invoke-direct {v1, p0}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;-><init>(Ljava/io/Reader;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 12
    .line 13
    :cond_0
    :try_start_0
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yyatEOF()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-nez p0, :cond_1

    .line 18
    .line 19
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yylex()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    const/4 p1, -0x1

    .line 24
    if-ne p0, p1, :cond_0

    .line 25
    .line 26
    :cond_1
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->getResult()Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 27
    .line 28
    .line 29
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    return-object p0

    .line 31
    :catch_0
    const/4 p0, 0x0

    .line 32
    invoke-static {p0, p0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method private setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 8
    .line 9
    :cond_0
    return-void
.end method

.method private final yyResetPosition()V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtBOL:Z

    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtEOF:Z

    .line 6
    .line 7
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 8
    .line 9
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 10
    .line 11
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 12
    .line 13
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 14
    .line 15
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 16
    .line 17
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yyline:I

    .line 18
    .line 19
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yycolumn:I

    .line 20
    .line 21
    const-wide/16 v0, 0x0

    .line 22
    .line 23
    iput-wide v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yychar:J

    .line 24
    .line 25
    return-void
.end method

.method private final yyatEOF()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtEOF:Z

    .line 2
    .line 3
    return p0
.end method

.method private final yybegin(I)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzLexicalState:I

    .line 2
    .line 3
    return-void
.end method

.method private final yycharat(I)C
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 2
    .line 3
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 4
    .line 5
    add-int/2addr p0, p1

    .line 6
    aget-char p0, v0, p0

    .line 7
    .line 8
    return p0
.end method

.method private final yyclose()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtEOF:Z

    .line 3
    .line 4
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 5
    .line 6
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzReader:Ljava/io/Reader;

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/io/Reader;->close()V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method private final yylength()I
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 2
    .line 3
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 4
    .line 5
    sub-int/2addr v0, p0

    .line 6
    return v0
.end method

.method private yylex()I
    .locals 14

    .line 1
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_TRANS:[I

    .line 6
    .line 7
    sget-object v3, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ROWMAP:[I

    .line 8
    .line 9
    sget-object v4, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ATTRIBUTE:[I

    .line 10
    .line 11
    :cond_0
    :goto_0
    :pswitch_0
    iget v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 12
    .line 13
    iput v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 14
    .line 15
    iput v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 16
    .line 17
    sget-object v6, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_LEXSTATE:[I

    .line 18
    .line 19
    iget v7, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzLexicalState:I

    .line 20
    .line 21
    aget v6, v6, v7

    .line 22
    .line 23
    iput v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzState:I

    .line 24
    .line 25
    aget v7, v4, v6

    .line 26
    .line 27
    const/4 v8, 0x1

    .line 28
    and-int/2addr v7, v8

    .line 29
    const/4 v9, -0x1

    .line 30
    if-ne v7, v8, :cond_1

    .line 31
    .line 32
    move v7, v6

    .line 33
    move v6, v5

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v6, v5

    .line 36
    move v7, v9

    .line 37
    :cond_2
    :goto_1
    if-ge v5, v0, :cond_3

    .line 38
    .line 39
    invoke-static {v1, v5, v0}, Ljava/lang/Character;->codePointAt([CII)I

    .line 40
    .line 41
    .line 42
    move-result v10

    .line 43
    invoke-static {v10}, Ljava/lang/Character;->charCount(I)I

    .line 44
    .line 45
    .line 46
    move-result v11

    .line 47
    add-int/2addr v11, v5

    .line 48
    :goto_2
    move v5, v11

    .line 49
    goto :goto_4

    .line 50
    :cond_3
    iget-boolean v10, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtEOF:Z

    .line 51
    .line 52
    if-eqz v10, :cond_4

    .line 53
    .line 54
    :goto_3
    move v10, v9

    .line 55
    goto :goto_5

    .line 56
    :cond_4
    iput v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 57
    .line 58
    iput v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 59
    .line 60
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzRefill()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    iget v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 65
    .line 66
    iget v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 67
    .line 68
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 69
    .line 70
    iget v10, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 71
    .line 72
    if-eqz v0, :cond_5

    .line 73
    .line 74
    move-object v1, v5

    .line 75
    move v0, v10

    .line 76
    goto :goto_3

    .line 77
    :cond_5
    invoke-static {v5, v1, v10}, Ljava/lang/Character;->codePointAt([CII)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    invoke-static {v0}, Ljava/lang/Character;->charCount(I)I

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    add-int/2addr v11, v1

    .line 86
    move v1, v10

    .line 87
    move v10, v0

    .line 88
    move v0, v1

    .line 89
    move-object v1, v5

    .line 90
    goto :goto_2

    .line 91
    :goto_4
    iget v11, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzState:I

    .line 92
    .line 93
    aget v11, v3, v11

    .line 94
    .line 95
    invoke-static {v10}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCMap(I)I

    .line 96
    .line 97
    .line 98
    move-result v12

    .line 99
    add-int/2addr v11, v12

    .line 100
    aget v11, v2, v11

    .line 101
    .line 102
    if-ne v11, v9, :cond_6

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_6
    iput v11, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzState:I

    .line 106
    .line 107
    aget v12, v4, v11

    .line 108
    .line 109
    and-int/lit8 v13, v12, 0x1

    .line 110
    .line 111
    if-ne v13, v8, :cond_2

    .line 112
    .line 113
    and-int/lit8 v6, v12, 0x8

    .line 114
    .line 115
    const/16 v7, 0x8

    .line 116
    .line 117
    if-ne v6, v7, :cond_20

    .line 118
    .line 119
    move v6, v5

    .line 120
    move v7, v11

    .line 121
    :goto_5
    iput v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 122
    .line 123
    if-ne v10, v9, :cond_7

    .line 124
    .line 125
    iget v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 126
    .line 127
    iget v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 128
    .line 129
    if-ne v5, v6, :cond_7

    .line 130
    .line 131
    iput-boolean v8, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzAtEOF:Z

    .line 132
    .line 133
    return v9

    .line 134
    :cond_7
    if-gez v7, :cond_8

    .line 135
    .line 136
    goto :goto_6

    .line 137
    :cond_8
    sget-object v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ACTION:[I

    .line 138
    .line 139
    aget v7, v5, v7

    .line 140
    .line 141
    :goto_6
    const/16 v5, 0x3f

    .line 142
    .line 143
    const/4 v6, 0x0

    .line 144
    packed-switch v7, :pswitch_data_0

    .line 145
    .line 146
    .line 147
    invoke-static {v8}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzScanError(I)V

    .line 148
    .line 149
    .line 150
    goto/16 :goto_0

    .line 151
    .line 152
    :pswitch_1
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 153
    .line 154
    if-nez v5, :cond_9

    .line 155
    .line 156
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;

    .line 157
    .line 158
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 159
    .line 160
    .line 161
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 162
    .line 163
    .line 164
    :cond_9
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 165
    .line 166
    .line 167
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 168
    .line 169
    .line 170
    move-result v5

    .line 171
    if-eqz v5, :cond_0

    .line 172
    .line 173
    return v9

    .line 174
    :pswitch_2
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 175
    .line 176
    if-nez v5, :cond_a

    .line 177
    .line 178
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Select;

    .line 179
    .line 180
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Select;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 181
    .line 182
    .line 183
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 184
    .line 185
    .line 186
    :cond_a
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 187
    .line 188
    .line 189
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 190
    .line 191
    .line 192
    move-result v5

    .line 193
    if-eqz v5, :cond_0

    .line 194
    .line 195
    return v9

    .line 196
    :pswitch_3
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 197
    .line 198
    if-nez v5, :cond_b

    .line 199
    .line 200
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;

    .line 201
    .line 202
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 203
    .line 204
    .line 205
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 206
    .line 207
    .line 208
    :cond_b
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 209
    .line 210
    .line 211
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 212
    .line 213
    .line 214
    move-result v5

    .line 215
    if-eqz v5, :cond_0

    .line 216
    .line 217
    return v9

    .line 218
    :pswitch_4
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 219
    .line 220
    if-nez v5, :cond_c

    .line 221
    .line 222
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Delete;

    .line 223
    .line 224
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Delete;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 225
    .line 226
    .line 227
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 228
    .line 229
    .line 230
    :cond_c
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 231
    .line 232
    .line 233
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 234
    .line 235
    .line 236
    move-result v5

    .line 237
    if-eqz v5, :cond_0

    .line 238
    .line 239
    return v9

    .line 240
    :pswitch_5
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 241
    .line 242
    if-nez v5, :cond_d

    .line 243
    .line 244
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Create;

    .line 245
    .line 246
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Create;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 247
    .line 248
    .line 249
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 250
    .line 251
    .line 252
    :cond_d
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 253
    .line 254
    .line 255
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 256
    .line 257
    .line 258
    move-result v5

    .line 259
    if-eqz v5, :cond_0

    .line 260
    .line 261
    return v9

    .line 262
    :pswitch_6
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 263
    .line 264
    if-nez v5, :cond_e

    .line 265
    .line 266
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Merge;

    .line 267
    .line 268
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Merge;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 269
    .line 270
    .line 271
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 272
    .line 273
    .line 274
    :cond_e
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 275
    .line 276
    .line 277
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 278
    .line 279
    .line 280
    move-result v5

    .line 281
    if-eqz v5, :cond_0

    .line 282
    .line 283
    return v9

    .line 284
    :pswitch_7
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 285
    .line 286
    if-nez v5, :cond_f

    .line 287
    .line 288
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Alter;

    .line 289
    .line 290
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Alter;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 291
    .line 292
    .line 293
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 294
    .line 295
    .line 296
    :cond_f
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 297
    .line 298
    .line 299
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 300
    .line 301
    .line 302
    move-result v5

    .line 303
    if-eqz v5, :cond_0

    .line 304
    .line 305
    return v9

    .line 306
    :pswitch_8
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 307
    .line 308
    if-nez v5, :cond_11

    .line 309
    .line 310
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 311
    .line 312
    if-nez v5, :cond_11

    .line 313
    .line 314
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 315
    .line 316
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->expectingOperationTarget()Z

    .line 317
    .line 318
    .line 319
    move-result v5

    .line 320
    if-eqz v5, :cond_10

    .line 321
    .line 322
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 323
    .line 324
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yytext()Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object v6

    .line 328
    invoke-virtual {v5, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleOperationTarget(Ljava/lang/String;)Z

    .line 329
    .line 330
    .line 331
    move-result v5

    .line 332
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 333
    .line 334
    goto :goto_7

    .line 335
    :cond_10
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 336
    .line 337
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleIdentifier()Z

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 342
    .line 343
    :cond_11
    :goto_7
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 344
    .line 345
    .line 346
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 347
    .line 348
    .line 349
    move-result v5

    .line 350
    if-eqz v5, :cond_0

    .line 351
    .line 352
    return v9

    .line 353
    :pswitch_9
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 354
    .line 355
    if-nez v5, :cond_12

    .line 356
    .line 357
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 358
    .line 359
    if-nez v5, :cond_12

    .line 360
    .line 361
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 362
    .line 363
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleNext()Z

    .line 364
    .line 365
    .line 366
    move-result v5

    .line 367
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 368
    .line 369
    :cond_12
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 370
    .line 371
    .line 372
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 373
    .line 374
    .line 375
    move-result v5

    .line 376
    if-eqz v5, :cond_0

    .line 377
    .line 378
    return v9

    .line 379
    :pswitch_a
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 380
    .line 381
    if-nez v5, :cond_13

    .line 382
    .line 383
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 384
    .line 385
    if-nez v5, :cond_13

    .line 386
    .line 387
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 388
    .line 389
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleJoin()Z

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 394
    .line 395
    :cond_13
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 396
    .line 397
    .line 398
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 399
    .line 400
    .line 401
    move-result v5

    .line 402
    if-eqz v5, :cond_0

    .line 403
    .line 404
    return v9

    .line 405
    :pswitch_b
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 406
    .line 407
    if-nez v5, :cond_14

    .line 408
    .line 409
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 410
    .line 411
    if-nez v5, :cond_14

    .line 412
    .line 413
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 414
    .line 415
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleInto()Z

    .line 416
    .line 417
    .line 418
    move-result v5

    .line 419
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 420
    .line 421
    :cond_14
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 422
    .line 423
    .line 424
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 425
    .line 426
    .line 427
    move-result v5

    .line 428
    if-eqz v5, :cond_0

    .line 429
    .line 430
    return v9

    .line 431
    :pswitch_c
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 432
    .line 433
    if-nez v5, :cond_16

    .line 434
    .line 435
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 436
    .line 437
    if-nez v5, :cond_16

    .line 438
    .line 439
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 440
    .line 441
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 442
    .line 443
    if-ne v5, v7, :cond_15

    .line 444
    .line 445
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Select;

    .line 446
    .line 447
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Select;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 448
    .line 449
    .line 450
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 451
    .line 452
    .line 453
    :cond_15
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 454
    .line 455
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleFrom()Z

    .line 456
    .line 457
    .line 458
    move-result v5

    .line 459
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 460
    .line 461
    :cond_16
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 462
    .line 463
    .line 464
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 465
    .line 466
    .line 467
    move-result v5

    .line 468
    if-eqz v5, :cond_0

    .line 469
    .line 470
    return v9

    .line 471
    :pswitch_d
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 472
    .line 473
    if-nez v5, :cond_17

    .line 474
    .line 475
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Drop;

    .line 476
    .line 477
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Drop;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 478
    .line 479
    .line 480
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 481
    .line 482
    .line 483
    :cond_17
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 484
    .line 485
    .line 486
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 487
    .line 488
    .line 489
    move-result v5

    .line 490
    if-eqz v5, :cond_0

    .line 491
    .line 492
    return v9

    .line 493
    :pswitch_e
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 494
    .line 495
    if-nez v5, :cond_18

    .line 496
    .line 497
    new-instance v5, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Call;

    .line 498
    .line 499
    invoke-direct {v5, p0, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Call;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 500
    .line 501
    .line 502
    invoke-direct {p0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->setOperation(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;)V

    .line 503
    .line 504
    .line 505
    :cond_18
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 506
    .line 507
    .line 508
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 509
    .line 510
    .line 511
    move-result v5

    .line 512
    if-eqz v5, :cond_0

    .line 513
    .line 514
    return v9

    .line 515
    :pswitch_f
    iput-boolean v8, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 516
    .line 517
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 518
    .line 519
    .line 520
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 521
    .line 522
    .line 523
    move-result v5

    .line 524
    if-eqz v5, :cond_0

    .line 525
    .line 526
    return v9

    .line 527
    :pswitch_10
    const/4 v5, 0x0

    .line 528
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 529
    .line 530
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 531
    .line 532
    .line 533
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 534
    .line 535
    .line 536
    move-result v5

    .line 537
    if-eqz v5, :cond_0

    .line 538
    .line 539
    return v9

    .line 540
    :pswitch_11
    iget-object v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->dialect:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 541
    .line 542
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->COUCHBASE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 543
    .line 544
    if-ne v6, v7, :cond_19

    .line 545
    .line 546
    iget-object v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 547
    .line 548
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 549
    .line 550
    .line 551
    goto :goto_8

    .line 552
    :cond_19
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 553
    .line 554
    if-nez v5, :cond_1a

    .line 555
    .line 556
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 557
    .line 558
    if-nez v5, :cond_1a

    .line 559
    .line 560
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 561
    .line 562
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleIdentifier()Z

    .line 563
    .line 564
    .line 565
    move-result v5

    .line 566
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 567
    .line 568
    :cond_1a
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 569
    .line 570
    .line 571
    :goto_8
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 572
    .line 573
    .line 574
    move-result v5

    .line 575
    if-eqz v5, :cond_0

    .line 576
    .line 577
    return v9

    .line 578
    :pswitch_12
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 579
    .line 580
    if-nez v5, :cond_1b

    .line 581
    .line 582
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 583
    .line 584
    if-nez v5, :cond_1b

    .line 585
    .line 586
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 587
    .line 588
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleIdentifier()Z

    .line 589
    .line 590
    .line 591
    move-result v5

    .line 592
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 593
    .line 594
    :cond_1b
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 595
    .line 596
    .line 597
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 598
    .line 599
    .line 600
    move-result v5

    .line 601
    if-eqz v5, :cond_0

    .line 602
    .line 603
    return v9

    .line 604
    :pswitch_13
    iget-object v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 605
    .line 606
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 607
    .line 608
    .line 609
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 610
    .line 611
    .line 612
    move-result v5

    .line 613
    if-eqz v5, :cond_0

    .line 614
    .line 615
    return v9

    .line 616
    :pswitch_14
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 617
    .line 618
    if-nez v5, :cond_1c

    .line 619
    .line 620
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 621
    .line 622
    if-nez v5, :cond_1c

    .line 623
    .line 624
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 625
    .line 626
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleComma()Z

    .line 627
    .line 628
    .line 629
    move-result v5

    .line 630
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 631
    .line 632
    :cond_1c
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 633
    .line 634
    .line 635
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 636
    .line 637
    .line 638
    move-result v5

    .line 639
    if-eqz v5, :cond_0

    .line 640
    .line 641
    return v9

    .line 642
    :pswitch_15
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 643
    .line 644
    if-nez v5, :cond_1d

    .line 645
    .line 646
    iget v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->parenLevel:I

    .line 647
    .line 648
    sub-int/2addr v5, v8

    .line 649
    iput v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->parenLevel:I

    .line 650
    .line 651
    :cond_1d
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 652
    .line 653
    .line 654
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 655
    .line 656
    .line 657
    move-result v5

    .line 658
    if-eqz v5, :cond_0

    .line 659
    .line 660
    return v9

    .line 661
    :pswitch_16
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 662
    .line 663
    if-nez v5, :cond_1e

    .line 664
    .line 665
    iget v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->parenLevel:I

    .line 666
    .line 667
    add-int/2addr v5, v8

    .line 668
    iput v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->parenLevel:I

    .line 669
    .line 670
    :cond_1e
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 671
    .line 672
    .line 673
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 674
    .line 675
    .line 676
    move-result v5

    .line 677
    if-eqz v5, :cond_0

    .line 678
    .line 679
    return v9

    .line 680
    :pswitch_17
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->insideComment:Z

    .line 681
    .line 682
    if-nez v5, :cond_1f

    .line 683
    .line 684
    iget-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 685
    .line 686
    if-nez v5, :cond_1f

    .line 687
    .line 688
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->operation:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 689
    .line 690
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->handleIdentifier()Z

    .line 691
    .line 692
    .line 693
    move-result v5

    .line 694
    iput-boolean v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->extractionDone:Z

    .line 695
    .line 696
    :cond_1f
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 697
    .line 698
    .line 699
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 700
    .line 701
    .line 702
    move-result v5

    .line 703
    if-eqz v5, :cond_0

    .line 704
    .line 705
    return v9

    .line 706
    :pswitch_18
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->builder:Ljava/lang/StringBuilder;

    .line 707
    .line 708
    const/16 v6, 0x20

    .line 709
    .line 710
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 711
    .line 712
    .line 713
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 714
    .line 715
    .line 716
    move-result v5

    .line 717
    if-eqz v5, :cond_0

    .line 718
    .line 719
    return v9

    .line 720
    :pswitch_19
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->appendCurrentFragment()V

    .line 721
    .line 722
    .line 723
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->isOverLimit()Z

    .line 724
    .line 725
    .line 726
    move-result v5

    .line 727
    if-eqz v5, :cond_0

    .line 728
    .line 729
    return v9

    .line 730
    :cond_20
    move v6, v5

    .line 731
    move v7, v11

    .line 732
    goto/16 :goto_1

    .line 733
    .line 734
    nop

    .line 735
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method private yypushback(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yylength()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-le p1, v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x2

    .line 8
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzScanError(I)V

    .line 9
    .line 10
    .line 11
    :cond_0
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 12
    .line 13
    sub-int/2addr v0, p1

    .line 14
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 15
    .line 16
    return-void
.end method

.method private final yyreset(Ljava/io/Reader;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzReader:Ljava/io/Reader;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEOFDone:Z

    .line 5
    .line 6
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->yyResetPosition()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzLexicalState:I

    .line 10
    .line 11
    const/16 p1, 0x800

    .line 12
    .line 13
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMaxBufferLen()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-static {p1, v0}, Ljava/lang/Math;->min(II)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 22
    .line 23
    array-length v0, v0

    .line 24
    if-le v0, p1, :cond_0

    .line 25
    .line 26
    new-array p1, p1, [C

    .line 27
    .line 28
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 29
    .line 30
    :cond_0
    return-void
.end method

.method private final yystate()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzLexicalState:I

    .line 2
    .line 3
    return p0
.end method

.method private final yytext()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 4
    .line 5
    iget v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 6
    .line 7
    iget p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 8
    .line 9
    sub-int/2addr p0, v2

    .line 10
    invoke-direct {v0, v1, v2, p0}, Ljava/lang/String;-><init>([CII)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method private static zzCMap(I)I
    .locals 3

    .line 1
    and-int/lit16 v0, p0, 0xff

    .line 2
    .line 3
    if-ne v0, p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_CMAP_BLOCKS:[I

    .line 6
    .line 7
    aget p0, p0, v0

    .line 8
    .line 9
    return p0

    .line 10
    :cond_0
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_CMAP_BLOCKS:[I

    .line 11
    .line 12
    sget-object v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_CMAP_TOP:[I

    .line 13
    .line 14
    shr-int/lit8 p0, p0, 0x8

    .line 15
    .line 16
    aget p0, v2, p0

    .line 17
    .line 18
    or-int/2addr p0, v0

    .line 19
    aget p0, v1, p0

    .line 20
    .line 21
    return p0
.end method

.method private zzCanGrow()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method private zzMaxBufferLen()I
    .locals 0

    .line 1
    const p0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method private zzRefill()Z
    .locals 6

    .line 1
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-lez v0, :cond_0

    .line 5
    .line 6
    iget v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 7
    .line 8
    iget v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 9
    .line 10
    add-int/2addr v2, v3

    .line 11
    iput v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 12
    .line 13
    iput v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 14
    .line 15
    iget-object v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 16
    .line 17
    sub-int/2addr v2, v0

    .line 18
    invoke-static {v3, v0, v3, v1, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 19
    .line 20
    .line 21
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 22
    .line 23
    iget v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 24
    .line 25
    sub-int/2addr v0, v2

    .line 26
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 27
    .line 28
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 29
    .line 30
    sub-int/2addr v0, v2

    .line 31
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 32
    .line 33
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 34
    .line 35
    sub-int/2addr v0, v2

    .line 36
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMarkedPos:I

    .line 37
    .line 38
    iput v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzStartRead:I

    .line 39
    .line 40
    :cond_0
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCurrentPos:I

    .line 41
    .line 42
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 43
    .line 44
    array-length v2, v2

    .line 45
    iget v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 46
    .line 47
    sub-int/2addr v2, v3

    .line 48
    if-lt v0, v2, :cond_1

    .line 49
    .line 50
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzCanGrow()Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_1

    .line 55
    .line 56
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 57
    .line 58
    array-length v0, v0

    .line 59
    mul-int/lit8 v0, v0, 0x2

    .line 60
    .line 61
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzMaxBufferLen()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    invoke-static {v0, v2}, Ljava/lang/Math;->min(II)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    new-array v0, v0, [C

    .line 70
    .line 71
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 72
    .line 73
    array-length v3, v2

    .line 74
    invoke-static {v2, v1, v0, v1, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 75
    .line 76
    .line 77
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 78
    .line 79
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 80
    .line 81
    iget v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 82
    .line 83
    add-int/2addr v0, v2

    .line 84
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 85
    .line 86
    iput v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 87
    .line 88
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 89
    .line 90
    array-length v2, v0

    .line 91
    iget v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 92
    .line 93
    sub-int/2addr v2, v3

    .line 94
    iget-object v4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzReader:Ljava/io/Reader;

    .line 95
    .line 96
    invoke-virtual {v4, v0, v3, v2}, Ljava/io/Reader;->read([CII)I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-nez v0, :cond_3

    .line 101
    .line 102
    if-nez v2, :cond_2

    .line 103
    .line 104
    new-instance v0, Ljava/io/EOFException;

    .line 105
    .line 106
    new-instance v1, Ljava/lang/StringBuilder;

    .line 107
    .line 108
    const-string v2, "Scan buffer limit reached ["

    .line 109
    .line 110
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 114
    .line 115
    array-length p0, p0

    .line 116
    const-string v2, "]"

    .line 117
    .line 118
    invoke-static {p0, v2, v1}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-direct {v0, p0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw v0

    .line 126
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 127
    .line 128
    const-string v0, "Reader returned 0 characters. See JFlex examples/zero-reader for a workaround."

    .line 129
    .line 130
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw p0

    .line 134
    :cond_3
    const/4 v3, 0x1

    .line 135
    if-lez v0, :cond_7

    .line 136
    .line 137
    iget v4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 138
    .line 139
    add-int/2addr v4, v0

    .line 140
    iput v4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 141
    .line 142
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 143
    .line 144
    sub-int/2addr v4, v3

    .line 145
    aget-char v4, v5, v4

    .line 146
    .line 147
    invoke-static {v4}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 148
    .line 149
    .line 150
    move-result v4

    .line 151
    if-eqz v4, :cond_6

    .line 152
    .line 153
    if-ne v0, v2, :cond_4

    .line 154
    .line 155
    iget v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 156
    .line 157
    sub-int/2addr v0, v3

    .line 158
    iput v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 159
    .line 160
    iput v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzFinalHighSurrogate:I

    .line 161
    .line 162
    goto :goto_0

    .line 163
    :cond_4
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzReader:Ljava/io/Reader;

    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/io/Reader;->read()I

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    const/4 v2, -0x1

    .line 170
    if-ne v0, v2, :cond_5

    .line 171
    .line 172
    return v3

    .line 173
    :cond_5
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzBuffer:[C

    .line 174
    .line 175
    iget v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 176
    .line 177
    add-int/lit8 v4, v3, 0x1

    .line 178
    .line 179
    iput v4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzEndRead:I

    .line 180
    .line 181
    int-to-char p0, v0

    .line 182
    aput-char p0, v2, v3

    .line 183
    .line 184
    :cond_6
    :goto_0
    return v1

    .line 185
    :cond_7
    return v3
.end method

.method private static zzScanError(I)V
    .locals 1

    .line 1
    :try_start_0
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ERROR_MSG:[Ljava/lang/String;

    .line 2
    .line 3
    aget-object p0, v0, p0
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :catch_0
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->ZZ_ERROR_MSG:[Ljava/lang/String;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    aget-object p0, p0, v0

    .line 10
    .line 11
    :goto_0
    new-instance v0, Ljava/lang/Error;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Ljava/lang/Error;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw v0
.end method

.method private static zzUnpackAction(Ljava/lang/String;I[I)I
    .locals 5

    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    add-int/lit8 v2, v1, 0x1

    .line 4
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v3

    add-int/lit8 v1, v1, 0x2

    .line 5
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v2

    :cond_0
    add-int/lit8 v4, p1, 0x1

    .line 6
    aput v2, p2, p1

    add-int/lit8 v3, v3, -0x1

    move p1, v4

    if-gtz v3, :cond_0

    goto :goto_0

    :cond_1
    return p1
.end method

.method private static zzUnpackAction()[I
    .locals 3

    const/16 v0, 0x7d

    .line 1
    new-array v0, v0, [I

    const/4 v1, 0x0

    .line 2
    const-string v2, "\u0001\u0000\u0001\u0001\u0001\u0002\u0001\u0001\u0001\u0003\u0001\u0001\u0001\u0004\u0001\u0005\u0002\u0001\u0001\u0006\u0001\u0001\u0002\u0007\u000f\u0008\u0001\u0001\u0001\u0000\u0001\t\u0001\u0000\u0001\u0003\u0001\u0000\u0001\u0007\u0001\n\u0001\u0000\u0001\u000b\u0002\u0000\u0008\u0008\u0001\u0001\n\u0008\u0001\u0000\u0001\u0003\u0001\u0000\u0001\u0007\u0002\u0000\u0013\u0008\u0001\u0007\u0003\u0008\u0001\u000c\u0003\u0008\u0001\r\u0001\u0008\u0001\u000e\u0002\u0008\u0001\u000f\u0001\u0010\u0001\u0008\u0001\u0011\u0004\u0008\u0001\u0012\u0001\u0013\u0005\u0008\u0001\u0014\u0003\u0008\u0001\u0015\u0001\u0008\u0001\u0016\u0001\u0017\u0001\u0008\u0001\u0018\u0001\u0019\u0001\u0008"

    invoke-static {v2, v1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackAction(Ljava/lang/String;I[I)I

    return-object v0
.end method

.method private static zzUnpackAttribute(Ljava/lang/String;I[I)I
    .locals 5

    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    add-int/lit8 v2, v1, 0x1

    .line 4
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v3

    add-int/lit8 v1, v1, 0x2

    .line 5
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v2

    :cond_0
    add-int/lit8 v4, p1, 0x1

    .line 6
    aput v2, p2, p1

    add-int/lit8 v3, v3, -0x1

    move p1, v4

    if-gtz v3, :cond_0

    goto :goto_0

    :cond_1
    return p1
.end method

.method private static zzUnpackAttribute()[I
    .locals 3

    const/16 v0, 0x7d

    .line 1
    new-array v0, v0, [I

    const/4 v1, 0x0

    .line 2
    const-string v2, "\u0001\u0000\u0001\t\u0004\u0001\u0002\t\u0002\u0001\u0001\t\u0013\u0001\u0001\u0000\u0001\u0001\u0001\u0000\u0001\u0001\u0001\u0000\u0001\u0001\u0001\t\u0001\u0000\u0001\t\u0002\u0000\u0013\u0001\u0001\u0000\u0001\u0001\u0001\u0000\u0001\u0001\u0002\u0000\u0013\u0001\u0001\t\'\u0001"

    invoke-static {v2, v1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackAttribute(Ljava/lang/String;I[I)I

    return-object v0
.end method

.method private static zzUnpackRowMap(Ljava/lang/String;I[I)I
    .locals 5

    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    add-int/lit8 v2, v1, 0x1

    .line 4
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v3

    shl-int/lit8 v3, v3, 0x10

    add-int/lit8 v4, p1, 0x1

    add-int/lit8 v1, v1, 0x2

    .line 5
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v2

    or-int/2addr v2, v3

    aput v2, p2, p1

    move p1, v4

    goto :goto_0

    :cond_0
    return p1
.end method

.method private static zzUnpackRowMap()[I
    .locals 3

    const/16 v0, 0x7d

    .line 1
    new-array v0, v0, [I

    const/4 v1, 0x0

    .line 2
    const-string v2, "\u0000\u0000\u0000%\u0000J\u0000o\u0000\u0094\u0000\u00b9\u0000%\u0000%\u0000\u00de\u0000\u0103\u0000%\u0000\u0128\u0000\u014d\u0000\u0172\u0000\u0197\u0000\u01bc\u0000\u01e1\u0000\u0206\u0000\u022b\u0000\u0250\u0000\u0275\u0000\u029a\u0000\u02bf\u0000\u02e4\u0000\u0309\u0000\u032e\u0000\u0353\u0000\u0378\u0000\u039d\u0000\u03c2\u0000o\u0000\u03e7\u0000\u040c\u0000\u0431\u0000\u00b9\u0000\u0456\u0000%\u0000\u0103\u0000%\u0000\u047b\u0000\u04a0\u0000\u04c5\u0000\u04ea\u0000\u050f\u0000\u0534\u0000\u0559\u0000\u057e\u0000\u05a3\u0000\u05c8\u0000\u01bc\u0000\u05ed\u0000\u0612\u0000\u0637\u0000\u065c\u0000\u0681\u0000\u06a6\u0000\u06cb\u0000\u06f0\u0000\u0715\u0000\u073a\u0000\u03c2\u0000\u075f\u0000\u0784\u0000\u047b\u0000\u07a9\u0000\u07ce\u0000\u07f3\u0000\u0818\u0000\u083d\u0000\u0862\u0000\u0887\u0000\u08ac\u0000\u08d1\u0000\u08f6\u0000\u091b\u0000\u0940\u0000\u0965\u0000\u098a\u0000\u09af\u0000\u09d4\u0000\u09f9\u0000\u0a1e\u0000\u0a43\u0000\u0a68\u0000\u0a8d\u0000%\u0000\u0ab2\u0000\u075f\u0000\u0ad7\u0000\u01bc\u0000\u0afc\u0000\u0b21\u0000\u0b46\u0000\u01bc\u0000\u0b6b\u0000\u01bc\u0000\u0b90\u0000\u0bb5\u0000\u01bc\u0000\u01bc\u0000\u0bda\u0000\u01bc\u0000\u0bff\u0000\u0c24\u0000\u0c49\u0000\u0c6e\u0000\u01bc\u0000\u01bc\u0000\u0c93\u0000\u0cb8\u0000\u0cdd\u0000\u0d02\u0000\u0d27\u0000\u01bc\u0000\u0d4c\u0000\u0d71\u0000\u0d96\u0000\u01bc\u0000\u0dbb\u0000\u01bc\u0000\u01bc\u0000\u0de0\u0000\u01bc\u0000\u01bc\u0000\u0e05"

    invoke-static {v2, v1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackRowMap(Ljava/lang/String;I[I)I

    return-object v0
.end method

.method private static zzUnpackcmap_blocks(Ljava/lang/String;I[I)I
    .locals 5

    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    add-int/lit8 v2, v1, 0x1

    .line 4
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v3

    add-int/lit8 v1, v1, 0x2

    .line 5
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v2

    :cond_0
    add-int/lit8 v4, p1, 0x1

    .line 6
    aput v2, p2, p1

    add-int/lit8 v3, v3, -0x1

    move p1, v4

    if-gtz v3, :cond_0

    goto :goto_0

    :cond_1
    return p1
.end method

.method private static zzUnpackcmap_blocks()[I
    .locals 3

    const/16 v0, 0x6d00

    .line 1
    new-array v0, v0, [I

    const/4 v1, 0x0

    .line 2
    const-string v2, "\t\u0000\u0002\u0001\u0002\u0000\u0001\u0001\u0012\u0000\u0001\u0001\u0001\u0000\u0001\u0002\u0001\u0000\u0001\u0003\u0002\u0000\u0001\u0004\u0001\u0005\u0001\u0006\u0001\u0007\u0001\u0008\u0001\t\u0001\u0008\u0001\n\u0001\u000b\u0001\u000c\t\r\u0007\u0000\u0001\u000e\u0001\u000f\u0001\u0010\u0001\u0011\u0001\u0012\u0001\u0013\u0001\u0014\u0001\u0015\u0001\u0016\u0001\u0017\u0001\u0015\u0001\u0018\u0001\u0019\u0001\u001a\u0001\u001b\u0001\u001c\u0001\u0015\u0001\u001d\u0001\u001e\u0001\u001f\u0001 \u0001!\u0001\"\u0001#\u0002\u0015\u0004\u0000\u0001\u0015\u0001$\u0001\u000e\u0001\u000f\u0001\u0010\u0001\u0011\u0001\u0012\u0001\u0013\u0001\u0014\u0001\u0015\u0001\u0016\u0001\u0017\u0001\u0015\u0001\u0018\u0001\u0019\u0001\u001a\u0001\u001b\u0001\u001c\u0001\u0015\u0001\u001d\u0001\u001e\u0001\u001f\u0001 \u0001!\u0001\"\u0001#\u0002\u0015/\u0000\u0001\u0015\n\u0000\u0001\u0015\u0004\u0000\u0001\u0015\u0005\u0000\u0017\u0015\u0001\u0000\u001f\u0015\u0001\u00008\u0015\u0002\u0016M\u0015\u0001\u001e\u0142\u0015\u0004\u0000\u000c\u0015\u000e\u0000\u0005\u0015\u0007\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0081\u0000\u0005\u0015\u0001\u0000\u0002\u0015\u0002\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0006\u0000\u0001\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0014\u0015\u0001\u0000S\u0015\u0001\u0000\u008b\u0015\u0008\u0000\u00a6\u0015\u0001\u0000&\u0015\u0002\u0000\u0001\u0015\u0006\u0000)\u0015G\u0000\u001b\u0015\u0004\u0000\u0004\u0015-\u0000+\u0015#\u0000\u0002\u0015\u0001\u0000c\u0015\u0001\u0000\u0001\u0015\u000f\u0000\u0002\u0015\u0007\u0000\u0002\u0015\n\u0000\u0003\u0015\u0002\u0000\u0001\u0015\u0010\u0000\u0001\u0015\u0001\u0000\u001e\u0015\u001d\u0000Y\u0015\u000b\u0000\u0001\u0015\u0018\u0000!\u0015\t\u0000\u0002\u0015\u0004\u0000\u0001\u0015\u0005\u0000\u0016\u0015\u0004\u0000\u0001\u0015\t\u0000\u0001\u0015\u0003\u0000\u0001\u0015\u0017\u0000\u0019\u0015\u0007\u0000\u000b\u00155\u0000\u0015\u0015\u0001\u0000\u0008\u0015F\u00006\u0015\u0003\u0000\u0001\u0015\u0012\u0000\u0001\u0015\u0007\u0000\n\u0015\u000f\u0000\u0010\u0015\u0004\u0000\u0008\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0004\u0015\u0003\u0000\u0001\u0015\u0010\u0000\u0001\u0015\r\u0000\u0002\u0015\u0001\u0000\u0003\u0015\u000e\u0000\u0002\u0015\n\u0000\u0001\u0015\u0008\u0000\u0006\u0015\u0004\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0002\u0015\u001f\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0013\u0000\u0003\u0015\u0010\u0000\t\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015\u0012\u0000\u0001\u0015\u000f\u0000\u0002\u0015\u0017\u0000\u0001\u0015\u000b\u0000\u0008\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015\u001e\u0000\u0002\u0015\u0001\u0000\u0003\u0015\u000f\u0000\u0001\u0015\u0011\u0000\u0001\u0015\u0001\u0000\u0006\u0015\u0003\u0000\u0003\u0015\u0001\u0000\u0004\u0015\u0003\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u0003\u0000\u0002\u0015\u0003\u0000\u0003\u0015\u0003\u0000\u000c\u0015\u0016\u0000\u0001\u00154\u0000\u0008\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0017\u0015\u0001\u0000\u0010\u0015\u0003\u0000\u0001\u0015\u001a\u0000\u0003\u0015\u0005\u0000\u0002\u0015\u001e\u0000\u0001\u0015\u0004\u0000\u0008\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0017\u0015\u0001\u0000\n\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015 \u0000\u0001\u0015\u0001\u0000\u0002\u0015\u000f\u0000\u0002\u0015\u0012\u0000\u0008\u0015\u0001\u0000\u0003\u0015\u0001\u0000)\u0015\u0002\u0000\u0001\u0015\u0010\u0000\u0001\u0015\u0005\u0000\u0003\u0015\u0008\u0000\u0003\u0015\u0018\u0000\u0006\u0015\u0005\u0000\u0012\u0015\u0003\u0000\u0018\u0015\u0001\u0000\t\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0007\u0015:\u00000\u0015\u0001\u0000\u0002\u0015\u000c\u0000\u0007\u0015:\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0018\u0015\u0001\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\u0002\u0015\t\u0000\u0001\u0015\u0002\u0000\u0005\u0015\u0001\u0000\u0001\u0015\u0015\u0000\u0004\u0015 \u0000\u0001\u0015?\u0000\u0008\u0015\u0001\u0000$\u0015\u001b\u0000\u0005\u0015s\u0000+\u0015\u0014\u0000\u0001\u0015\u0010\u0000\u0006\u0015\u0004\u0000\u0004\u0015\u0003\u0000\u0001\u0015\u0003\u0000\u0002\u0015\u0007\u0000\u0003\u0015\u0004\u0000\r\u0015\u000c\u0000\u0001\u0015\u0011\u0000&\u0015\u0001\u0000\u0001\u0015\u0005\u0000\u0001\u0015\u0002\u0000+\u0015\u0001\u0000\u014d\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0002\u0000)\u0015\u0001\u0000\u0004\u0015\u0002\u0000!\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u000f\u0015\u0001\u00009\u0015\u0001\u0000\u0004\u0015\u0002\u0000C\u0015%\u0000\u0010\u0015\u0010\u0000V\u0015\u0002\u0000\u0006\u0015\u0003\u0000\u016c\u0015\u0002\u0000\u0011\u0015\u0001\u0000\u001a\u0015\u0005\u0000K\u0015\u0006\u0000\u0008\u0015\u0007\u0000\r\u0015\u0001\u0000\u0004\u0015\u000e\u0000\u0012\u0015\u000e\u0000\u0012\u0015\u000e\u0000\r\u0015\u0001\u0000\u0003\u0015\u000f\u00004\u0015#\u0000\u0001\u0015\u0004\u0000\u0001\u0015C\u0000Y\u0015\u0007\u0000\u0005\u0015\u0002\u0000\"\u0015\u0001\u0000\u0001\u0015\u0005\u0000F\u0015\n\u0000\u001f\u00151\u0000\u001e\u0015\u0002\u0000\u0005\u0015\u000b\u0000,\u0015\u0004\u0000\u001a\u00156\u0000\u0017\u0015\t\u00005\u0015R\u0000\u0001\u0015]\u0000/\u0015\u0011\u0000\u0007\u00157\u0000\u001e\u0015\r\u0000\u0002\u0015\n\u0000,\u0015\u001a\u0000$\u0015)\u0000\u0003\u0015\n\u0000$\u0015\u0002\u0000\t\u0015\u0007\u0000+\u0015\u0002\u0000\u0003\u0015)\u0000\u0004\u0015\u0001\u0000\u0006\u0015\u0001\u0000\u0002\u0015\u0003\u0000\u0001\u0015\u0005\u0000\u00c0\u0015@\u0000\u0016\u0015\u0002\u0000\u0006\u0015\u0002\u0000&\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0008\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u001f\u0015\u0002\u00005\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0003\u0015\u0001\u0000\u0007\u0015\u0003\u0000\u0004\u0015\u0002\u0000\u0006\u0015\u0004\u0000\r\u0015\u0005\u0000\u0003\u0015\u0001\u0000\u0007\u0015t\u0000\u0001\u0015\r\u0000\u0001\u0015\u0010\u0000\r\u0015e\u0000\u0001\u0015\u0004\u0000\u0001\u0015\u0002\u0000\n\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0005\u0015\u0006\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u000b\u0015\u0002\u0000\u0004\u0015\u0005\u0000\u0005\u0015\u0004\u0000\u0001\u00154\u0000\u0002\u0015\u017b\u0000/\u0015\u0001\u0000/\u0015\u0001\u0000\u0085\u0015\u0006\u0000\u0004\u0015\u0003\u0000\u0002\u0015\u000c\u0000&\u0015\u0001\u0000\u0001\u0015\u0005\u0000\u0001\u0015\u0002\u00008\u0015\u0007\u0000\u0001\u0015\u0010\u0000\u0017\u0015\t\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0007\u0015P\u0000\u0001\u0015\u00d5\u0000\u0002\u0015*\u0000\u0005\u0015\u0005\u0000\u0002\u0015\u0004\u0000V\u0015\u0006\u0000\u0003\u0015\u0001\u0000Z\u0015\u0001\u0000\u0004\u0015\u0005\u0000+\u0015\u0001\u0000^\u0015\u0011\u0000\u001b\u00155\u0000\u00c6\u0015J\u0000\u00f0\u0015\u0010\u0000\u008d\u0015C\u0000.\u0015\u0002\u0000\r\u0015\u0003\u0000\u0010\u0015\n\u0000\u0002\u0015\u0014\u0000/\u0015\u0010\u0000\u001f\u0015\u0002\u0000F\u00151\u0000\t\u0015\u0002\u0000g\u0015\u0002\u00005\u0015\u0002\u0000\u0005\u00150\u0000\u000b\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0017\u0015\u001d\u00004\u0015\u000e\u00002\u0015>\u0000\u0006\u0015\u0003\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u000b\u0000\u001c\u0015\n\u0000\u0017\u0015\u0019\u0000\u001d\u0015\u0007\u0000/\u0015\u001c\u0000\u0001\u0015\u0010\u0000\u0005\u0015\u0001\u0000\n\u0015\n\u0000\u0005\u0015\u0001\u0000)\u0015\u0017\u0000\u0003\u0015\u0001\u0000\u0008\u0015\u0014\u0000\u0017\u0015\u0003\u0000\u0001\u0015\u0003\u00002\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0002\u0015\u0002\u0000\u0005\u0015\u0002\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0018\u0000\u0003\u0015\u0002\u0000\u000b\u0015\u0007\u0000\u0003\u0015\u000c\u0000\u0006\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0006\u0015\t\u0000\u0007\u0015\u0001\u0000\u0007\u0015\u0001\u0000+\u0015\u0001\u0000\u000c\u0015\u0008\u0000s\u0015\u001d\u0000\u00a4\u0015\u000c\u0000\u0017\u0015\u0004\u00001\u0015\u0004\u0000n\u0015\u0002\u0000j\u0015&\u0000\u0007\u0015\u000c\u0000\u0005\u0015\u0005\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\r\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0002\u0015\u0001\u0000l\u0015!\u0000k\u0015\u0012\u0000@\u0015\u0002\u00006\u0015(\u0000\u000c\u0015t\u0000\u0005\u0015\u0001\u0000\u0087\u0015$\u0000\u001a\u0015\u0006\u0000\u001a\u0015\u000b\u0000Y\u0015\u0003\u0000\u0006\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0006\u0015\u0002\u0000\u0003\u0015#\u0000\u000c\u0015\u0001\u0000\u001a\u0015\u0001\u0000\u0013\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u000f\u0015\u0002\u0000\u000e\u0015\"\u0000{\u0015\u0085\u0000\u001d\u0015\u0003\u00001\u0015/\u0000 \u0015\r\u0000\u0014\u0015\u0001\u0000\u0008\u0015\u0006\u0000&\u0015\n\u0000\u001e\u0015\u0002\u0000$\u0015\u0004\u0000\u0008\u00150\u0000\u009e\u0015\u0012\u0000$\u0015\u0004\u0000$\u0015\u0004\u0000(\u0015\u0008\u00004\u0015\u009c\u00007\u0015\t\u0000\u0016\u0015\n\u0000\u0008\u0015\u0098\u0000\u0006\u0015\u0002\u0000\u0001\u0015\u0001\u0000,\u0015\u0001\u0000\u0002\u0015\u0003\u0000\u0001\u0015\u0002\u0000\u0017\u0015\n\u0000\u0017\u0015\t\u0000\u001f\u0015A\u0000\u0013\u0015\u0001\u0000\u0002\u0015\n\u0000\u0016\u0015\n\u0000\u001a\u0015F\u00008\u0015\u0006\u0000\u0002\u0015@\u0000\u0001\u0015\u000f\u0000\u0004\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u001d\u0015*\u0000\u001d\u0015\u0003\u0000\u001d\u0015#\u0000\u0008\u0015\u0001\u0000\u001c\u0015\u001b\u00006\u0015\n\u0000\u0016\u0015\n\u0000\u0013\u0015\r\u0000\u0012\u0015n\u0000I\u00157\u00003\u0015\r\u00003\u0015\r\u0000$\u0015\u00dc\u0000\u001d\u0015\n\u0000\u0001\u0015\u0008\u0000\u0016\u0015\u009a\u0000\u0017\u0015\u000c\u00005\u0015K\u0000-\u0015 \u0000\u0019\u0015\u001a\u0000$\u0015\u001d\u0000\u0001\u0015\u000b\u0000#\u0015\u0003\u0000\u0001\u0015\u000c\u00000\u0015\u000e\u0000\u0004\u0015\u0015\u0000\u0001\u0015\u0001\u0000\u0001\u0015#\u0000\u0012\u0015\u0001\u0000\u0019\u0015T\u0000\u0007\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u000f\u0015\u0001\u0000\n\u0015\u0007\u0000/\u0015&\u0000\u0008\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0016\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0005\u0015\u0003\u0000\u0001\u0015\u0012\u0000\u0001\u0015\u000c\u0000\u0005\u0015\u009e\u00005\u0015\u0012\u0000\u0004\u0015\u0014\u0000\u0001\u0015 \u00000\u0015\u0014\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u00b8\u0000/\u0015)\u0000\u0004\u0015$\u00000\u0015\u0014\u0000\u0001\u0015;\u0000+\u0015\r\u0000\u0001\u0015G\u0000\u001b\u0015\u00e5\u0000,\u0015t\u0000@\u0015\u001f\u0000\u0001\u0015\u00a0\u0000\u0008\u0015\u0002\u0000\'\u0015\u0010\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u001c\u0000\u0001\u0015\n\u0000(\u0015\u0007\u0000\u0001\u0015\u0015\u0000\u0001\u0015\u000b\u0000.\u0015\u0013\u0000\u0001\u0015\"\u00009\u0015\u0007\u0000\t\u0015\u0001\u0000%\u0015\u0011\u0000\u0001\u00151\u0000\u001e\u0015p\u0000\u0007\u0015\u0001\u0000\u0002\u0015\u0001\u0000&\u0015\u0015\u0000\u0001\u0015\u0019\u0000\u0006\u0015\u0001\u0000\u0002\u0015\u0001\u0000 \u0015\u000e\u0000\u0001\u0015\u0147\u0000\u0013\u0015\r\u0000\u009a\u0015\u00e6\u0000\u00c4\u0015\u00bc\u0000/\u0015\u00d1\u0000G\u0015\u00b9\u00009\u0015\u0007\u0000\u001f\u0015q\u0000\u001e\u0015\u0012\u00000\u0015\u0010\u0000\u0004\u0015\u001f\u0000\u0015\u0015\u0005\u0000\u0013\u0015\u00b0\u0000@\u0015\u0080\u0000K\u0015\u0005\u0000\u0001\u0015B\u0000\r\u0015@\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u001c\u0000\u00f8\u0015\u0008\u0000\u00f3\u0015\r\u0000\u001f\u00151\u0000\u0003\u0015\u0011\u0000\u0004\u0015\u0008\u0000\u018c\u0015\u0004\u0000k\u0015\u0005\u0000\r\u0015\u0003\u0000\t\u0015\u0007\u0000\n\u0015f\u0000U\u0015\u0001\u0000G\u0015\u0001\u0000\u0002\u0015\u0002\u0000\u0001\u0015\u0002\u0000\u0002\u0015\u0002\u0000\u0004\u0015\u0001\u0000\u000c\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0007\u0015\u0001\u0000A\u0015\u0001\u0000\u0004\u0015\u0002\u0000\u0008\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u001c\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0001\u0015\u0003\u0000\u0007\u0015\u0001\u0000\u0154\u0015\u0002\u0000\u0019\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u001f\u0015\u0001\u0000\u0019\u0015\u0001\u0000\u0008\u00154\u0000-\u0015\n\u0000\u0007\u0015\u0010\u0000\u0001\u0015\u0171\u0000,\u0015\u0014\u0000\u00c5\u0015;\u0000D\u0015\u0007\u0000\u0001\u0015\u00b4\u0000\u0004\u0015\u0001\u0000\u001b\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0006\u0000\u0001\u0015\u0004\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0003\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0001\u0015\u0001\u0000\u0002\u0015\u0001\u0000\u0001\u0015\u0002\u0000\u0004\u0015\u0001\u0000\u0007\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0004\u0015\u0001\u0000\u0001\u0015\u0001\u0000\n\u0015\u0001\u0000\u0011\u0015\u0005\u0000\u0003\u0015\u0001\u0000\u0005\u0015\u0001\u0000\u0011\u0015D\u0000\u00d7\u0015)\u00005\u0015\u000b\u0000\u00de\u0015\u0002\u0000\u0182\u0015\u000e\u0000\u0131\u0015\u001f\u0000\u001e\u0015\u00e2\u0000"

    invoke-static {v2, v1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackcmap_blocks(Ljava/lang/String;I[I)I

    return-object v0
.end method

.method private static zzUnpackcmap_top(Ljava/lang/String;I[I)I
    .locals 5

    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    add-int/lit8 v2, v1, 0x1

    .line 4
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v3

    add-int/lit8 v1, v1, 0x2

    .line 5
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v2

    :cond_0
    add-int/lit8 v4, p1, 0x1

    .line 6
    aput v2, p2, p1

    add-int/lit8 v3, v3, -0x1

    move p1, v4

    if-gtz v3, :cond_0

    goto :goto_0

    :cond_1
    return p1
.end method

.method private static zzUnpackcmap_top()[I
    .locals 3

    const/16 v0, 0x1100

    .line 1
    new-array v0, v0, [I

    const/4 v1, 0x0

    .line 2
    const-string v2, "\u0001\u0000\u0001\u0100\u0001\u0200\u0001\u0300\u0001\u0400\u0001\u0500\u0001\u0600\u0001\u0700\u0001\u0800\u0001\u0900\u0001\u0a00\u0001\u0b00\u0001\u0c00\u0001\u0d00\u0001\u0e00\u0001\u0f00\u0001\u1000\u0001\u1100\u0001\u1200\u0001\u1300\u0001\u1400\u0001\u1100\u0001\u1500\u0001\u1600\u0001\u1700\u0001\u1800\u0001\u1900\u0001\u1a00\u0001\u1b00\u0001\u1c00\u0001\u1100\u0001\u1d00\u0001\u1e00\u0001\u1f00\n\u2000\u0001\u2100\u0001\u2200\u0001\u2300\u0001\u2000\u0001\u2400\u0001\u2500\u0002\u2000\u0019\u1100\u0001\u2600Q\u1100\u0001\u2700\u0004\u1100\u0001\u2800\u0001\u1100\u0001\u2900\u0001\u2a00\u0001\u2b00\u0001\u2c00\u0001\u2d00\u0001\u2e00+\u1100\u0001\u2f00!\u2000\u0001\u1100\u0001\u3000\u0001\u3100\u0001\u1100\u0001\u3200\u0001\u3300\u0001\u3400\u0001\u3500\u0001\u2000\u0001\u3600\u0001\u3700\u0001\u3800\u0001\u3900\u0001\u1100\u0001\u3a00\u0001\u3b00\u0001\u3c00\u0001\u3d00\u0001\u3e00\u0001\u3f00\u0001\u4000\u0001\u2000\u0001\u4100\u0001\u4200\u0001\u4300\u0001\u4400\u0001\u4500\u0001\u4600\u0001\u4700\u0001\u4800\u0001\u4900\u0001\u4a00\u0001\u4b00\u0001\u4c00\u0001\u2000\u0001\u4d00\u0001\u4e00\u0001\u4f00\u0001\u2000\u0003\u1100\u0001\u5000\u0001\u5100\u0001\u5200\n\u2000\u0004\u1100\u0001\u5300\u000f\u2000\u0002\u1100\u0001\u5400!\u2000\u0002\u1100\u0001\u5500\u0001\u5600\u0002\u2000\u0001\u5700\u0001\u5800\u0017\u1100\u0001\u5900\u0002\u1100\u0001\u5a00%\u2000\u0001\u1100\u0001\u5b00\u0001\u5c00\t\u2000\u0001\u5d00\u0017\u2000\u0001\u5e00\u0001\u5f00\u0001\u6000\u0001\u6100\t\u2000\u0001\u6200\u0001\u6300\u0005\u2000\u0001\u6400\u0001\u6500\u0004\u2000\u0001\u6600\u0011\u2000\u00a6\u1100\u0001\u6700\u0010\u1100\u0001\u6800\u0001\u6900\u0015\u1100\u0001\u6a00\u001c\u1100\u0001\u6b00\u000c\u2000\u0002\u1100\u0001\u6c00\u0e05\u2000"

    invoke-static {v2, v1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpackcmap_top(Ljava/lang/String;I[I)I

    return-object v0
.end method

.method private static zzUnpacktrans(Ljava/lang/String;I[I)I
    .locals 5

    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    add-int/lit8 v2, v1, 0x1

    .line 4
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v3

    add-int/lit8 v1, v1, 0x2

    .line 5
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    move-result v2

    add-int/lit8 v2, v2, -0x1

    :cond_0
    add-int/lit8 v4, p1, 0x1

    .line 6
    aput v2, p2, p1

    add-int/lit8 v3, v3, -0x1

    move p1, v4

    if-gtz v3, :cond_0

    goto :goto_0

    :cond_1
    return p1
.end method

.method private static zzUnpacktrans()[I
    .locals 3

    const/16 v0, 0xe2a

    .line 1
    new-array v0, v0, [I

    const/4 v1, 0x0

    .line 2
    const-string v2, "\u0001\u0002\u0001\u0003\u0001\u0004\u0001\u0005\u0001\u0006\u0001\u0007\u0001\u0008\u0001\t\u0001\n\u0001\u000b\u0001\n\u0001\u000c\u0001\r\u0001\u000e\u0001\u000f\u0001\u0010\u0001\u0011\u0001\u0012\u0001\u0013\u0001\u0014\u0002\u0010\u0001\u0015\u0001\u0016\u0001\u0010\u0001\u0017\u0001\u0018\u0001\u0010\u0001\u0019\u0001\u0010\u0001\u001a\u0001\u001b\u0001\u001c\u0001\u001d\u0002\u0010\u0001\u001e&\u0000\u0001\u0003#\u0000\u0002\u001f\u0001 \"\u001f\u0003\u0000\u0001!\u0008\u0000\u0002\"\u0017\u0000\u0004#\u0001$ #\u000b\u0000\u0001%!\u0000\u0001&\u0001\u0000\u0001&\u0001\u0000\u0002\u000e\u001e\u0000\u0001\'%\u0000\u0001\u000e\u0001\u0000\u0001\u000e\u0001\u0000\u0002\u000e\u0004\u0000\u0001\u000e\u0010\u0000\u0001(\t\u0000\u0001\u000e\u0001\u0000\u0001\u000e\u0001\u0000\u0002\u000e\u0004\u0000\u0001\u000e\u001c\u0000\u0001)\u0001\u0000\u000c\u0010\u0001*\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0018\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001+\u000e\u0010\u0001,\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001-\u0003\u0010\u0001.\n\u0010\u0001/\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0017\u0010\u00010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u00011\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0007\u0010\u00012\u0006\u0010\u00013\t\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u00014\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u00015\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u00016\u0008\u0010\u00017\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u00018\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u00019\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001:\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0010\u0010\u0001;\u0007\u0010\u000b\u0000\u0001)\u0001\u0000\n\u0010\u0001<\r\u0010\u0001\u0000$=\u0001>\u0002\u0000\u0001\u001f\u0007\u0000\u0001)\u001a\u0000\u0003!\u0001?!!\u000c\u0000\u0002\"\u001b\u0000\u0001#,\u0000\u0008@\u0013\u0000\u0001A\u000b\u0000\u0016\u0010\u0001B\n\u0000\u0001)\u0001\u0000\u0013\u0010\u0001C\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001D\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001E\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001F\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001G\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001H\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\n\u0010\u0001I\r\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001J\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u0005\u0010\u0001K\u000c\u0010\u0001L\u0001M\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\n\u0010\u0001N\r\u0010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u0001O\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0017\u0010\u0001P\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u00012\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001Q\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001R\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0003\u0010\u0001S\u0014\u0010\u000b\u0000\u0001)\u0001\u0000\u0005\u0010\u0001T\u0012\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001U\u0011\u0010\u000b\u0000\u0001)\u001d\u0000\u0001V!\u0000\u0002A\u0001W\"A$B\u0001X\n\u0000\u0001)\u0001\u0000\u0006\u0010\u0001Y\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001Z\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001[\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001\\\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001]\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0010\u0010\u0001^\u0007\u0010\u000b\u0000\u0001)\u0001\u0000\u0012\u0010\u0001_\u0005\u0010\u000b\u0000\u0001)\u0001\u0000\r\u0010\u0001`\n\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001a\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001b\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u000f\u0010\u0001c\u0008\u0010\u000b\u0000\u0001)\u0001\u0000\u000e\u0010\u0001d\t\u0010\u000b\u0000\u0001)\u0001\u0000\u0008\u0010\u0001e\u000f\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001f\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0004\u0010\u0001g\u0013\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001h\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u000c\u0010\u0001i\u000b\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001j\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0016\u0010\u0001k\u0001\u0010\u0003\u0000\u0001A\u0007\u0000\u0001)$\u0000\u0001)\u0001\u0000\u0011\u0010\u0001l\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001m\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0003\u0010\u0001n\u0014\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001o\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001p\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0017\u0010\u0001k\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u0001q\u0006\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001r\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001s\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0004\u0010\u0001t\u0013\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001k\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001u\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001v\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0002\u0010\u0001w\u0015\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001x\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0012\u0010\u00012\u0005\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001y\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0005\u0010\u0001z\u0012\u0010\u000b\u0000\u0001)\u0001\u0000\u0013\u0010\u0001{\u0004\u0010\u000b\u0000\u0001)\u0001\u0000\u0006\u0010\u0001|\u0011\u0010\u000b\u0000\u0001)\u0001\u0000\u0012\u0010\u0001i\u0005\u0010\u000b\u0000\u0001)\u0001\u0000\u0014\u0010\u0001}\u0003\u0010\u000b\u0000\u0001)\u0001\u0000\u0011\u0010\u0001i\u0006\u0010\u0001\u0000"

    invoke-static {v2, v1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->zzUnpacktrans(Ljava/lang/String;I[I)I

    return-object v0
.end method
